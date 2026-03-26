package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func (s *paymentsAppService) CreatePayment(ctx context.Context, req *appv1.CreatePaymentRequest) (*appv1.CreatePaymentResponse, error) {
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
func (s *paymentsAppService) ListPaymentHistory(ctx context.Context, req *appv1.ListPaymentHistoryRequest) (*appv1.ListPaymentHistoryResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())

	rows, total, err := s.paymentRepository.ListHistoryByUser(ctx, result.UserID, paymentKindSubscription, paymentKindWalletTopup, walletTransactionTypeTopup, limit, offset)
	if err != nil {
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
			InvoiceId:     buildInvoiceID(row.InvoiceID),
			Kind:          row.Kind,
			TermMonths:    row.TermMonths,
			PaymentMethod: normalizeOptionalPaymentMethod(row.PaymentMethod),
			ExpiresAt:     timeToProto(row.ExpiresAt),
			CreatedAt:     timeToProto(row.CreatedAt),
		})
	}

	hasPrev := page > 1 && total > 0
	hasNext := int64(offset)+int64(len(items)) < total
	return &appv1.ListPaymentHistoryResponse{
		Payments: items,
		Total:    total,
		Page:     page,
		Limit:    limit,
		HasPrev:  hasPrev,
		HasNext:  hasNext,
	}, nil
}

func (s *paymentsAppService) TopupWallet(ctx context.Context, req *appv1.TopupWalletRequest) (*appv1.TopupWalletResponse, error) {
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

	if err := s.paymentRepository.CreateWalletTopupAndNotification(ctx, result.UserID, transaction, notification); err != nil {
		s.logger.Error("Failed to top up wallet", "error", err)
		return nil, status.Error(codes.Internal, "Failed to top up wallet")
	}

	balance, err := s.billingRepository.GetWalletBalance(ctx, result.UserID)
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
func (s *paymentsAppService) DownloadInvoice(ctx context.Context, req *appv1.DownloadInvoiceRequest) (*appv1.DownloadInvoiceResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Invoice not found")
	}

	paymentRecord, err := s.paymentRepository.GetByIDAndUser(ctx, id, result.UserID)
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

	topup, err := s.paymentRepository.GetStandaloneTopupByIDAndUser(ctx, id, result.UserID, walletTransactionTypeTopup)
	if err == nil {
		return &appv1.DownloadInvoiceResponse{
			Filename:    buildInvoiceFilename(topup.ID),
			ContentType: "text/plain; charset=utf-8",
			Content:     buildTopupInvoice(topup),
		}, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		s.logger.Error("Failed to load topup invoice", "error", err)
		return nil, status.Error(codes.Internal, "Failed to download invoice")
	}

	return nil, status.Error(codes.NotFound, "Invoice not found")
}
