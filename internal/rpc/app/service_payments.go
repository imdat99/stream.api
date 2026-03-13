package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	paymentapi "stream.api/internal/api/payment"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func (s *appServices) CreatePayment(ctx context.Context, req *appv1.CreatePaymentRequest) (*appv1.CreatePaymentResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	planID := strings.TrimSpace(req.GetPlanId())
	if planID == "" {
		return nil, status.Error(codes.InvalidArgument, "Plan ID is required")
	}
	if !isAllowedTermMonths(req.GetTermMonths()) {
		return nil, status.Error(codes.InvalidArgument, "Term months must be one of 1, 3, 6, or 12")
	}

	paymentMethod := normalizePaymentMethod(req.GetPaymentMethod())
	if paymentMethod == "" {
		return nil, status.Error(codes.InvalidArgument, "Payment method must be wallet or topup")
	}

	var planRecord model.Plan
	if err := s.db.WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		s.logger.Error("Failed to load plan", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}

	totalAmount := planRecord.Price * float64(req.GetTermMonths())
	if totalAmount < 0 {
		return nil, status.Error(codes.InvalidArgument, "Amount must be greater than or equal to 0")
	}

	statusValue := "SUCCESS"
	provider := "INTERNAL"
	currency := normalizeCurrency(nil)
	transactionID := buildTransactionID("sub")
	now := time.Now().UTC()

	paymentRecord := &model.Payment{
		ID:            uuid.New().String(),
		UserID:        result.UserID,
		PlanID:        &planRecord.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &statusValue,
		Provider:      &provider,
		TransactionID: &transactionID,
	}

	invoiceID := buildInvoiceID(paymentRecord.ID)
	var subscription *model.PlanSubscription
	var walletBalance float64

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(ctx, tx, result.UserID); err != nil {
			return err
		}

		currentSubscription, err := model.GetLatestPlanSubscription(ctx, tx, result.UserID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		baseExpiry := now
		if currentSubscription != nil && currentSubscription.ExpiresAt.After(baseExpiry) {
			baseExpiry = currentSubscription.ExpiresAt.UTC()
		}
		newExpiry := baseExpiry.AddDate(0, int(req.GetTermMonths()), 0)

		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, result.UserID)
		if err != nil {
			return err
		}
		shortfall := maxFloat(totalAmount-currentWalletBalance, 0)

		if paymentMethod == paymentMethodWallet && shortfall > 0 {
			return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Insufficient wallet balance", map[string]interface{}{
				"payment_method": paymentMethod,
				"wallet_balance": currentWalletBalance,
				"total_amount":   totalAmount,
				"shortfall":      shortfall,
			})
		}

		topupAmount := 0.0
		if paymentMethod == paymentMethodTopup {
			if req.TopupAmount == nil {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount is required when payment method is topup", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
				})
			}

			topupAmount = maxFloat(req.GetTopupAmount(), 0)
			if topupAmount <= 0 {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than 0", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
				})
			}
			if topupAmount < shortfall {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than or equal to the required shortfall", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
					"topup_amount":   topupAmount,
				})
			}
		}

		if err := tx.Create(paymentRecord).Error; err != nil {
			return err
		}

		walletUsedAmount := totalAmount

		if paymentMethod == paymentMethodTopup {
			topupTransaction := &model.WalletTransaction{
				ID:         uuid.New().String(),
				UserID:     result.UserID,
				Type:       walletTransactionTypeTopup,
				Amount:     topupAmount,
				Currency:   model.StringPtr(currency),
				Note:       model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", planRecord.Name, req.GetTermMonths())),
				PaymentID:  &paymentRecord.ID,
				PlanID:     &planRecord.ID,
				TermMonths: int32Ptr(req.GetTermMonths()),
			}
			if err := tx.Create(topupTransaction).Error; err != nil {
				return err
			}
		}

		debitTransaction := &model.WalletTransaction{
			ID:         uuid.New().String(),
			UserID:     result.UserID,
			Type:       walletTransactionTypeSubscriptionDebit,
			Amount:     -totalAmount,
			Currency:   model.StringPtr(currency),
			Note:       model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", planRecord.Name, req.GetTermMonths())),
			PaymentID:  &paymentRecord.ID,
			PlanID:     &planRecord.ID,
			TermMonths: int32Ptr(req.GetTermMonths()),
		}
		if err := tx.Create(debitTransaction).Error; err != nil {
			return err
		}

		subscription = &model.PlanSubscription{
			ID:            uuid.New().String(),
			UserID:        result.UserID,
			PaymentID:     paymentRecord.ID,
			PlanID:        planRecord.ID,
			TermMonths:    req.GetTermMonths(),
			PaymentMethod: paymentMethod,
			WalletAmount:  walletUsedAmount,
			TopupAmount:   topupAmount,
			StartedAt:     now,
			ExpiresAt:     newExpiry,
		}
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).
			Where("id = ?", result.UserID).
			Update("plan_id", planRecord.ID).Error; err != nil {
			return err
		}

		notification := buildSubscriptionNotification(result.UserID, paymentRecord.ID, invoiceID, &planRecord, subscription)
		if err := tx.Create(notification).Error; err != nil {
			return err
		}

		walletBalance, err = model.GetWalletBalance(ctx, tx, result.UserID)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		s.logger.Error("Failed to create payment", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}

	return &appv1.CreatePaymentResponse{
		Payment:       toProtoPayment(paymentRecord),
		Subscription:  toProtoPlanSubscription(subscription),
		WalletBalance: walletBalance,
		InvoiceId:     invoiceID,
		Message:       "Payment completed successfully",
	}, nil
}
func (s *appServices) ListPaymentHistory(ctx context.Context, _ *appv1.ListPaymentHistoryRequest) (*appv1.ListPaymentHistoryResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	var rows []paymentRow
	if err := s.db.WithContext(ctx).
		Table("payment AS p").
		Select("p.id, p.amount, p.currency, p.status, p.plan_id, pl.name AS plan_name, ps.term_months, ps.payment_method, ps.expires_at, p.created_at").
		Joins("LEFT JOIN plan AS pl ON pl.id = p.plan_id").
		Joins("LEFT JOIN plan_subscriptions AS ps ON ps.payment_id = p.id").
		Where("p.user_id = ?", result.UserID).
		Order("p.created_at DESC").
		Scan(&rows).Error; err != nil {
		s.logger.Error("Failed to fetch payment history", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch payment history")
	}

	items := make([]paymentapi.PaymentHistoryItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, paymentapi.PaymentHistoryItem{
			ID:            row.ID,
			Amount:        row.Amount,
			Currency:      normalizeCurrency(row.Currency),
			Status:        normalizePaymentStatus(row.Status),
			PlanID:        row.PlanID,
			PlanName:      row.PlanName,
			InvoiceID:     buildInvoiceID(row.ID),
			Kind:          paymentKindSubscription,
			TermMonths:    row.TermMonths,
			PaymentMethod: normalizeOptionalPaymentMethod(row.PaymentMethod),
			ExpiresAt:     row.ExpiresAt,
			CreatedAt:     row.CreatedAt,
		})
	}

	var topups []model.WalletTransaction
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND type = ? AND payment_id IS NULL", result.UserID, walletTransactionTypeTopup).
		Order("created_at DESC").
		Find(&topups).Error; err != nil {
		s.logger.Error("Failed to fetch wallet topups", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch payment history")
	}

	for _, topup := range topups {
		createdAt := topup.CreatedAt
		items = append(items, paymentapi.PaymentHistoryItem{
			ID:        topup.ID,
			Amount:    topup.Amount,
			Currency:  normalizeCurrency(topup.Currency),
			Status:    "success",
			InvoiceID: buildInvoiceID(topup.ID),
			Kind:      paymentKindWalletTopup,
			CreatedAt: createdAt,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		left := time.Time{}
		right := time.Time{}
		if items[i].CreatedAt != nil {
			left = *items[i].CreatedAt
		}
		if items[j].CreatedAt != nil {
			right = *items[j].CreatedAt
		}
		return right.After(left)
	})

	payload := make([]*appv1.PaymentHistoryItem, 0, len(items))
	for _, item := range items {
		copyItem := item
		payload = append(payload, toProtoPaymentHistoryItem(&copyItem))
	}

	return &appv1.ListPaymentHistoryResponse{Payments: payload}, nil
}
func (s *appServices) TopupWallet(ctx context.Context, req *appv1.TopupWalletRequest) (*appv1.TopupWalletResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	amount := req.GetAmount()
	if amount < 1 {
		return nil, status.Error(codes.InvalidArgument, "Amount must be at least 1")
	}

	transaction := &model.WalletTransaction{
		ID:       uuid.New().String(),
		UserID:   result.UserID,
		Type:     walletTransactionTypeTopup,
		Amount:   amount,
		Currency: model.StringPtr("USD"),
		Note:     model.StringPtr(fmt.Sprintf("Wallet top-up of %.2f USD", amount)),
	}

	notification := &model.Notification{
		ID:      uuid.New().String(),
		UserID:  result.UserID,
		Type:    "billing.topup",
		Title:   "Wallet credited",
		Message: fmt.Sprintf("Your wallet has been credited with %.2f USD.", amount),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]interface{}{
			"wallet_transaction_id": transaction.ID,
			"invoice_id":            buildInvoiceID(transaction.ID),
		})),
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(ctx, tx, result.UserID); err != nil {
			return err
		}
		if err := tx.Create(transaction).Error; err != nil {
			return err
		}
		if err := tx.Create(notification).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		s.logger.Error("Failed to top up wallet", "error", err)
		return nil, status.Error(codes.Internal, "Failed to top up wallet")
	}

	balance, err := model.GetWalletBalance(ctx, s.db, result.UserID)
	if err != nil {
		s.logger.Error("Failed to calculate wallet balance", "error", err)
		return nil, status.Error(codes.Internal, "Failed to top up wallet")
	}

	return &appv1.TopupWalletResponse{
		WalletTransaction: toProtoWalletTransaction(transaction),
		WalletBalance:     balance,
		InvoiceId:         buildInvoiceID(transaction.ID),
	}, nil
}
func (s *appServices) DownloadInvoice(ctx context.Context, req *appv1.DownloadInvoiceRequest) (*appv1.DownloadInvoiceResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Invoice not found")
	}

	paymentRecord, err := query.Payment.WithContext(ctx).
		Where(query.Payment.ID.Eq(id), query.Payment.UserID.Eq(result.UserID)).
		First()
	if err == nil {
		invoiceText, filename, buildErr := s.buildPaymentInvoice(ctx, paymentRecord)
		if buildErr != nil {
			s.logger.Error("Failed to build payment invoice", "error", buildErr)
			return nil, status.Error(codes.Internal, "Failed to download invoice")
		}
		return &appv1.DownloadInvoiceResponse{
			Filename:    filename,
			ContentType: "text/plain; charset=utf-8",
			Content:     invoiceText,
		}, nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.logger.Error("Failed to load payment invoice", "error", err)
		return nil, status.Error(codes.Internal, "Failed to download invoice")
	}

	var topup model.WalletTransaction
	if err := s.db.WithContext(ctx).
		Where("id = ? AND user_id = ? AND type = ? AND payment_id IS NULL", id, result.UserID, walletTransactionTypeTopup).
		First(&topup).Error; err == nil {
		return &appv1.DownloadInvoiceResponse{
			Filename:    buildInvoiceFilename(topup.ID),
			ContentType: "text/plain; charset=utf-8",
			Content:     buildTopupInvoice(&topup),
		}, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		s.logger.Error("Failed to load topup invoice", "error", err)
		return nil, status.Error(codes.Internal, "Failed to download invoice")
	}

	return nil, status.Error(codes.NotFound, "Invoice not found")
}
