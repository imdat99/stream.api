package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
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

	planRecord, err := s.loadPaymentPlanForUser(ctx, planID)
	if err != nil {
		return nil, err
	}

	resultValue, err := s.executePaymentFlow(ctx, paymentExecutionInput{
		UserID:        result.UserID,
		Plan:          planRecord,
		TermMonths:    req.GetTermMonths(),
		PaymentMethod: paymentMethod,
		TopupAmount:   req.TopupAmount,
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		s.logger.Error("Failed to create payment", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}

	return &appv1.CreatePaymentResponse{
		Payment:       toProtoPayment(resultValue.Payment),
		Subscription:  toProtoPlanSubscription(resultValue.Subscription),
		WalletBalance: resultValue.WalletBalance,
		InvoiceId:     resultValue.InvoiceID,
		Message:       "Payment completed successfully",
	}, nil
}
func (s *appServices) ListPaymentHistory(ctx context.Context, req *appv1.ListPaymentHistoryRequest) (*appv1.ListPaymentHistoryResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())

	type paymentHistoryRow struct {
		ID            string     `gorm:"column:id"`
		Amount        float64    `gorm:"column:amount"`
		Currency      *string    `gorm:"column:currency"`
		Status        *string    `gorm:"column:status"`
		PlanID        *string    `gorm:"column:plan_id"`
		PlanName      *string    `gorm:"column:plan_name"`
		TermMonths    *int32     `gorm:"column:term_months"`
		PaymentMethod *string    `gorm:"column:payment_method"`
		ExpiresAt     *time.Time `gorm:"column:expires_at"`
		CreatedAt     *time.Time `gorm:"column:created_at"`
	}

	var rows []paymentHistoryRow
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

	items := make([]*appv1.PaymentHistoryItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, &appv1.PaymentHistoryItem{
			Id:            row.ID,
			Amount:        row.Amount,
			Currency:      normalizeCurrency(row.Currency),
			Status:        normalizePaymentStatus(row.Status),
			PlanId:        row.PlanID,
			PlanName:      row.PlanName,
			InvoiceId:     buildInvoiceID(row.ID),
			Kind:          paymentKindSubscription,
			TermMonths:    row.TermMonths,
			PaymentMethod: normalizeOptionalPaymentMethod(row.PaymentMethod),
			ExpiresAt:     timeToProto(row.ExpiresAt),
			CreatedAt:     timeToProto(row.CreatedAt),
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
		items = append(items, &appv1.PaymentHistoryItem{
			Id:        topup.ID,
			Amount:    topup.Amount,
			Currency:  normalizeCurrency(topup.Currency),
			Status:    "success",
			InvoiceId: buildInvoiceID(topup.ID),
			Kind:      paymentKindWalletTopup,
			CreatedAt: timeToProto(topup.CreatedAt),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		left := time.Time{}
		right := time.Time{}
		if items[i].CreatedAt != nil {
			left = items[i].CreatedAt.AsTime()
		}
		if items[j].CreatedAt != nil {
			right = items[j].CreatedAt.AsTime()
		}
		if right.Equal(left) {
			return items[i].GetId() > items[j].GetId()
		}
		return right.After(left)
	})

	total := int64(len(items))
	hasPrev := page > 1 && total > 0
	if offset >= len(items) {
		return &appv1.ListPaymentHistoryResponse{Payments: []*appv1.PaymentHistoryItem{}, Total: total, Page: page, Limit: limit, HasPrev: hasPrev, HasNext: false}, nil
	}
	end := offset + int(limit)
	if end > len(items) {
		end = len(items)
	}
	hasNext := end < len(items)
	return &appv1.ListPaymentHistoryResponse{Payments: items[offset:end], Total: total, Page: page, Limit: limit, HasPrev: hasPrev, HasNext: hasNext}, nil
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
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
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
	if !errors.Is(err, gorm.ErrRecordNotFound) {
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
