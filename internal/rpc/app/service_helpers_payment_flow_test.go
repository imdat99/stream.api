package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"stream.api/internal/database/model"
)

func TestValidatePaymentFunding(t *testing.T) {

	baseInput := paymentExecutionInput{PaymentMethod: paymentMethodWallet}

	tests := []struct {
		name          string
		input         paymentExecutionInput
		totalAmount   float64
		walletBalance float64
		wantTopup     float64
		wantCode      codes.Code
		wantMessage   string
	}{
		{
			name:          "wallet đủ tiền",
			input:         baseInput,
			totalAmount:   30,
			walletBalance: 30,
			wantTopup:     0,
		},
		{
			name:          "wallet thiếu tiền",
			input:         baseInput,
			totalAmount:   50,
			walletBalance: 20,
			wantCode:      codes.InvalidArgument,
			wantMessage:   "Insufficient wallet balance",
		},
		{
			name:          "topup thiếu amount",
			input:         paymentExecutionInput{PaymentMethod: paymentMethodTopup},
			totalAmount:   50,
			walletBalance: 20,
			wantCode:      codes.InvalidArgument,
			wantMessage:   "Top-up amount is required when payment method is topup",
		},
		{
			name:          "topup amount <= 0",
			input:         paymentExecutionInput{PaymentMethod: paymentMethodTopup, TopupAmount: ptrFloat64(0)},
			totalAmount:   50,
			walletBalance: 20,
			wantCode:      codes.InvalidArgument,
			wantMessage:   "Top-up amount must be greater than 0",
		},
		{
			name:          "topup amount nhỏ hơn shortfall",
			input:         paymentExecutionInput{PaymentMethod: paymentMethodTopup, TopupAmount: ptrFloat64(20)},
			totalAmount:   50,
			walletBalance: 20,
			wantCode:      codes.InvalidArgument,
			wantMessage:   "Top-up amount must be greater than or equal to the required shortfall",
		},
		{
			name:          "topup hợp lệ",
			input:         paymentExecutionInput{PaymentMethod: paymentMethodTopup, TopupAmount: ptrFloat64(30)},
			totalAmount:   50,
			walletBalance: 20,
			wantTopup:     30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePaymentFunding(context.Background(), tt.input, tt.totalAmount, tt.walletBalance)
			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("validatePaymentFunding() error = %v", err)
				}
				if got != tt.wantTopup {
					t.Fatalf("validatePaymentFunding() topup = %v, want %v", got, tt.wantTopup)
				}
				return
			}

			if err == nil {
				t.Fatalf("validatePaymentFunding() error = nil, want %v", tt.wantCode)
			}
			if status.Code(err) != tt.wantCode {
				t.Fatalf("validatePaymentFunding() code = %v, want %v", status.Code(err), tt.wantCode)
			}
			if got := err.Error(); !strings.Contains(got, tt.wantMessage) {
				t.Fatalf("validatePaymentFunding() message = %q, want contains %q", got, tt.wantMessage)
			}
		})
	}
}

func TestExecutePaymentFlow_CreatesExpectedRecords(t *testing.T) {

	db := newTestDB(t)
	services := newTestAppServices(t, db)

	user := seedTestUser(t, db, model.User{
		ID:          uuid.NewString(),
		Email:       "payer@example.com",
		Role:        ptrString("USER"),
		StorageUsed: 0,
	})
	plan := seedTestPlan(t, db, model.Plan{
		ID:            uuid.NewString(),
		Name:          "Pro",
		Price:         10,
		Cycle:         "monthly",
		StorageLimit:  100,
		UploadLimit:   10,
		DurationLimit: 0,
		QualityLimit:  "1080p",
		Features:      []string{"priority"},
		IsActive:      ptrBool(true),
	})
	seedWalletTransaction(t, db, model.WalletTransaction{
		ID:       uuid.NewString(),
		UserID:   user.ID,
		Type:     walletTransactionTypeTopup,
		Amount:   5,
		Currency: ptrString("USD"),
		Note:     ptrString("Initial funds"),
	})

	result, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{
		UserID:        user.ID,
		Plan:          &plan,
		TermMonths:    3,
		PaymentMethod: paymentMethodTopup,
		TopupAmount:   ptrFloat64(25),
	})
	if err != nil {
		t.Fatalf("executePaymentFlow() error = %v", err)
	}
	if result == nil || result.Payment == nil || result.Subscription == nil {
		t.Fatalf("executePaymentFlow() returned incomplete result: %#v", result)
	}
	if result.InvoiceID != buildInvoiceID(result.Payment.ID) {
		t.Fatalf("invoice id = %q, want %q", result.InvoiceID, buildInvoiceID(result.Payment.ID))
	}
	if result.WalletBalance != 0 {
		t.Fatalf("wallet balance = %v, want 0", result.WalletBalance)
	}

	payment := mustLoadPayment(t, db, result.Payment.ID)
	if payment.Amount != 30 {
		t.Fatalf("payment amount = %v, want 30", payment.Amount)
	}
	if payment.PlanID == nil || *payment.PlanID != plan.ID {
		t.Fatalf("payment plan_id = %v, want %s", payment.PlanID, plan.ID)
	}
	if normalizePaymentStatus(payment.Status) != "success" {
		t.Fatalf("payment status = %q, want success", normalizePaymentStatus(payment.Status))
	}

	subscription := mustLoadSubscriptionByPayment(t, db, payment.ID)
	if subscription.PaymentID != payment.ID {
		t.Fatalf("subscription payment_id = %q, want %q", subscription.PaymentID, payment.ID)
	}
	if subscription.PlanID != plan.ID {
		t.Fatalf("subscription plan_id = %q, want %q", subscription.PlanID, plan.ID)
	}
	if subscription.TermMonths != 3 {
		t.Fatalf("subscription term_months = %d, want 3", subscription.TermMonths)
	}
	if subscription.PaymentMethod != paymentMethodTopup {
		t.Fatalf("subscription payment_method = %q, want %q", subscription.PaymentMethod, paymentMethodTopup)
	}
	if subscription.WalletAmount != 30 {
		t.Fatalf("subscription wallet_amount = %v, want 30", subscription.WalletAmount)
	}
	if subscription.TopupAmount != 25 {
		t.Fatalf("subscription topup_amount = %v, want 25", subscription.TopupAmount)
	}
	if !subscription.ExpiresAt.After(subscription.StartedAt) {
		t.Fatalf("subscription expires_at = %v should be after started_at = %v", subscription.ExpiresAt, subscription.StartedAt)
	}

	walletTransactions := mustListWalletTransactionsByPayment(t, db, payment.ID)
	if len(walletTransactions) != 2 {
		t.Fatalf("wallet transaction count = %d, want 2", len(walletTransactions))
	}
	if walletTransactions[0].Amount != 25 || walletTransactions[0].Type != walletTransactionTypeTopup {
		t.Fatalf("first wallet transaction = %#v, want topup amount 25", walletTransactions[0])
	}
	if walletTransactions[1].Amount != -30 || walletTransactions[1].Type != walletTransactionTypeSubscriptionDebit {
		t.Fatalf("second wallet transaction = %#v, want debit amount -30", walletTransactions[1])
	}

	updatedUser := mustLoadUser(t, db, user.ID)
	if updatedUser.PlanID == nil || *updatedUser.PlanID != plan.ID {
		t.Fatalf("user plan_id = %v, want %s", updatedUser.PlanID, plan.ID)
	}

	notifications := mustListNotificationsByUser(t, db, user.ID)
	if len(notifications) != 1 {
		t.Fatalf("notification count = %d, want 1", len(notifications))
	}
	notification := notifications[0]
	if notification.Type != "billing.subscription" {
		t.Fatalf("notification type = %q, want %q", notification.Type, "billing.subscription")
	}
	if !strings.Contains(notification.Message, plan.Name) {
		t.Fatalf("notification message = %q, want plan name", notification.Message)
	}
	if notification.Metadata == nil {
		t.Fatal("notification metadata = nil")
	}

	var metadataPayload map[string]any
	if err := json.Unmarshal([]byte(*notification.Metadata), &metadataPayload); err != nil {
		t.Fatalf("unmarshal notification metadata: %v", err)
	}
	if metadataPayload["invoice_id"] != result.InvoiceID {
		t.Fatalf("metadata invoice_id = %v, want %q", metadataPayload["invoice_id"], result.InvoiceID)
	}
	if metadataPayload["payment_id"] != payment.ID {
		t.Fatalf("metadata payment_id = %v, want %q", metadataPayload["payment_id"], payment.ID)
	}
	if metadataPayload["payment_method"] != paymentMethodTopup {
		t.Fatalf("metadata payment_method = %v, want %q", metadataPayload["payment_method"], paymentMethodTopup)
	}
	if metadataPayload["wallet_amount"] != 30.0 {
		t.Fatalf("metadata wallet_amount = %v, want 30", metadataPayload["wallet_amount"])
	}
	if metadataPayload["topup_amount"] != 25.0 {
		t.Fatalf("metadata topup_amount = %v, want 25", metadataPayload["topup_amount"])
	}
}
