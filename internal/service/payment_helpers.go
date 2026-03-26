package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func statusErrorWithBody(ctx context.Context, grpcCode codes.Code, httpCode int, message string, data any) error {
	body := apiErrorBody{
		Code:    httpCode,
		Message: message,
		Data:    data,
	}
	encoded, err := json.Marshal(body)
	if err == nil {
		_ = grpc.SetTrailer(ctx, metadata.Pairs("x-error-body", string(encoded)))
	}
	return status.Error(grpcCode, message)
}

func (s *paymentsAppService) loadPaymentPlanForUser(ctx context.Context, planID string) (*model.Plan, error) {
	planRecord, err := s.planRepository.GetByID(ctx, planID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		s.logger.Error("Failed to load plan", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}
	return planRecord, nil
}

func (s *appServices) loadPaymentPlanForAdmin(ctx context.Context, planID string) (*model.Plan, error) {
	planRecord, err := s.planRepository.GetByID(ctx, planID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}
	return planRecord, nil
}

func (s *appServices) loadPaymentUserForAdmin(ctx context.Context, userID string) (*model.User, error) {
	user, err := s.userRepository.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	return user, nil
}

func (s *appServices) executePaymentFlow(ctx context.Context, input paymentExecutionInput) (*paymentExecutionResult, error) {
	totalAmount := input.Plan.Price * float64(input.TermMonths)
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
		UserID:        input.UserID,
		PlanID:        &input.Plan.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &statusValue,
		Provider:      &provider,
		TransactionID: &transactionID,
	}
	invoiceID := buildInvoiceID(paymentRecord.ID)

	result := &paymentExecutionResult{
		Payment:   paymentRecord,
		InvoiceID: invoiceID,
	}

	subscription, walletBalance, err := s.paymentRepository.ExecuteSubscriptionPayment(
		ctx,
		input.UserID,
		input.Plan,
		input.TermMonths,
		input.PaymentMethod,
		paymentRecord,
		invoiceID,
		now,
		func(currentWalletBalance float64) (float64, error) {
			return validatePaymentFunding(ctx, input, totalAmount, currentWalletBalance)
		},
	)
	if err != nil {
		return nil, err
	}
	result.Subscription = subscription
	result.WalletBalance = walletBalance
	return result, nil
}

func validatePaymentFunding(ctx context.Context, input paymentExecutionInput, totalAmount, currentWalletBalance float64) (float64, error) {
	shortfall := maxFloat(totalAmount-currentWalletBalance, 0)
	if input.PaymentMethod == paymentMethodWallet && shortfall > 0 {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Insufficient wallet balance", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if input.PaymentMethod != paymentMethodTopup {
		return 0, nil
	}
	if input.TopupAmount == nil {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount is required when payment method is topup", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	topupAmount := maxFloat(*input.TopupAmount, 0)
	if topupAmount <= 0 {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than 0", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if topupAmount < shortfall {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than or equal to the required shortfall", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
			"topup_amount":   topupAmount,
		})
	}
	return topupAmount, nil
}

func (s *paymentsAppService) buildPaymentInvoice(ctx context.Context, paymentRecord *model.Payment) (string, string, error) {
	details, err := s.loadPaymentInvoiceDetails(ctx, paymentRecord)
	if err != nil {
		return "", "", err
	}

	createdAt := formatOptionalTimestamp(paymentRecord.CreatedAt)
	lines := []string{
		"Stream API Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(paymentRecord.ID)),
		fmt.Sprintf("Payment ID: %s", paymentRecord.ID),
		fmt.Sprintf("User ID: %s", paymentRecord.UserID),
		fmt.Sprintf("Plan: %s", details.PlanName),
		fmt.Sprintf("Amount: %.2f %s", paymentRecord.Amount, normalizeCurrency(paymentRecord.Currency)),
		fmt.Sprintf("Status: %s", strings.ToUpper(normalizePaymentStatus(paymentRecord.Status))),
		fmt.Sprintf("Provider: %s", strings.ToUpper(stringValue(paymentRecord.Provider))),
		fmt.Sprintf("Payment Method: %s", strings.ToUpper(details.PaymentMethod)),
		fmt.Sprintf("Transaction ID: %s", stringValue(paymentRecord.TransactionID)),
	}

	if details.TermMonths != nil {
		lines = append(lines, fmt.Sprintf("Term: %d month(s)", *details.TermMonths))
	}
	if details.ExpiresAt != nil {
		lines = append(lines, fmt.Sprintf("Valid Until: %s", details.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	if details.WalletAmount > 0 {
		lines = append(lines, fmt.Sprintf("Wallet Applied: %.2f %s", details.WalletAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	if details.TopupAmount > 0 {
		lines = append(lines, fmt.Sprintf("Top-up Added: %.2f %s", details.TopupAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	lines = append(lines, fmt.Sprintf("Created At: %s", createdAt))

	return strings.Join(lines, "\n"), buildInvoiceFilename(paymentRecord.ID), nil
}

func buildTopupInvoice(transaction *model.WalletTransaction) string {
	createdAt := formatOptionalTimestamp(transaction.CreatedAt)
	return strings.Join([]string{
		"Stream API Wallet Top-up Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(transaction.ID)),
		fmt.Sprintf("Wallet Transaction ID: %s", transaction.ID),
		fmt.Sprintf("User ID: %s", transaction.UserID),
		fmt.Sprintf("Amount: %.2f %s", transaction.Amount, normalizeCurrency(transaction.Currency)),
		"Status: SUCCESS",
		fmt.Sprintf("Type: %s", strings.ToUpper(transaction.Type)),
		fmt.Sprintf("Note: %s", model.StringValue(transaction.Note)),
		fmt.Sprintf("Created At: %s", createdAt),
	}, "\n")
}

func (s *paymentsAppService) loadPaymentInvoiceDetails(ctx context.Context, paymentRecord *model.Payment) (*paymentInvoiceDetails, error) {
	details := &paymentInvoiceDetails{
		PlanName:      "Unknown plan",
		PaymentMethod: paymentMethodWallet,
	}

	if paymentRecord.PlanID != nil && strings.TrimSpace(*paymentRecord.PlanID) != "" {
		planRecord, err := s.planRepository.GetByID(ctx, *paymentRecord.PlanID)
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
		} else {
			details.PlanName = planRecord.Name
		}
	}

	subscription, err := s.paymentRepository.GetSubscriptionByPaymentID(ctx, paymentRecord.ID)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return details, nil
	}

	details.TermMonths = &subscription.TermMonths
	details.PaymentMethod = normalizePaymentMethod(subscription.PaymentMethod)
	if details.PaymentMethod == "" {
		details.PaymentMethod = paymentMethodWallet
	}
	details.ExpiresAt = &subscription.ExpiresAt
	details.WalletAmount = subscription.WalletAmount
	details.TopupAmount = subscription.TopupAmount

	return details, nil
}

func isAllowedTermMonths(value int32) bool {
	_, ok := allowedTermMonths[value]
	return ok
}

func maxFloat(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}

func formatOptionalTimestamp(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func mustMarshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func messageResponse(message string) *appv1.MessageResponse {
	return &appv1.MessageResponse{Message: message}
}
