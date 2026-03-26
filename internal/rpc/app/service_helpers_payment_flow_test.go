package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"stream.api/internal/database/model"
	"stream.api/internal/modules/common"
	paymentsmodule "stream.api/internal/modules/payments"
)

func TestValidatePaymentFunding(t *testing.T) {
	baseInput := paymentsmodule.ExecutionInput{PaymentMethod: common.PaymentMethodWallet}

	tests := []struct {
		name          string
		input         paymentsmodule.ExecutionInput
		totalAmount   float64
		walletBalance float64
		wantTopup     float64
		wantCode      codes.Code
		wantMessage   string
	}{
		{name: "wallet đủ tiền", input: baseInput, totalAmount: 30, walletBalance: 30, wantTopup: 0},
		{name: "wallet thiếu tiền", input: baseInput, totalAmount: 50, walletBalance: 20, wantCode: codes.InvalidArgument, wantMessage: "Insufficient wallet balance"},
		{name: "topup thiếu amount", input: paymentsmodule.ExecutionInput{PaymentMethod: common.PaymentMethodTopup}, totalAmount: 50, walletBalance: 20, wantCode: codes.InvalidArgument, wantMessage: "Top-up amount is required when payment method is topup"},
		{name: "topup amount <= 0", input: paymentsmodule.ExecutionInput{PaymentMethod: common.PaymentMethodTopup, TopupAmount: ptrFloat64(0)}, totalAmount: 50, walletBalance: 20, wantCode: codes.InvalidArgument, wantMessage: "Top-up amount must be greater than 0"},
		{name: "topup amount nhỏ hơn shortfall", input: paymentsmodule.ExecutionInput{PaymentMethod: common.PaymentMethodTopup, TopupAmount: ptrFloat64(20)}, totalAmount: 50, walletBalance: 20, wantCode: codes.InvalidArgument, wantMessage: "Top-up amount must be greater than or equal to the required shortfall"},
		{name: "topup hợp lệ", input: paymentsmodule.ExecutionInput{PaymentMethod: common.PaymentMethodTopup, TopupAmount: ptrFloat64(30)}, totalAmount: 50, walletBalance: 20, wantTopup: 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := paymentsmodule.ValidatePaymentFunding(tt.input, tt.totalAmount, tt.walletBalance)
			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("ValidatePaymentFunding() error = %v", err)
				}
				if got != tt.wantTopup {
					t.Fatalf("ValidatePaymentFunding() topup = %v, want %v", got, tt.wantTopup)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePaymentFunding() error = nil, want %v", tt.wantCode)
			}
			if validationErr, ok := err.(*paymentsmodule.PaymentValidationError); !ok || codes.Code(validationErr.GRPCCode) != tt.wantCode {
				gotCode := codes.Unknown
				if ok {
					gotCode = codes.Code(validationErr.GRPCCode)
				}
				t.Fatalf("ValidatePaymentFunding() code = %v, want %v", gotCode, tt.wantCode)
			}
			if got := err.Error(); !strings.Contains(got, tt.wantMessage) {
				t.Fatalf("ValidatePaymentFunding() message = %q, want contains %q", got, tt.wantMessage)
			}
		})
	}
}

func TestExecutePaymentFlow_CreatesExpectedRecords(t *testing.T) {
	db := newTestDB(t)
	services := newTestAppServices(t, db)

	user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "payer@example.com", Role: ptrString("USER"), StorageUsed: 0})
	plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 10, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, DurationLimit: 0, QualityLimit: "1080p", Features: []string{"priority"}, IsActive: ptrBool(true)})
	seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: common.WalletTransactionTypeTopup, Amount: 5, Currency: ptrString("USD"), Note: ptrString("Initial funds")})

	result, err := services.paymentsModule.ExecutePaymentFlow(context.Background(), paymentsmodule.ExecutionInput{UserID: user.ID, Plan: &plan, TermMonths: 3, PaymentMethod: common.PaymentMethodTopup, TopupAmount: ptrFloat64(25)})
	if err != nil {
		t.Fatalf("ExecutePaymentFlow() error = %v", err)
	}
	if result == nil || result.Payment == nil || result.Subscription == nil {
		t.Fatalf("ExecutePaymentFlow() returned incomplete result: %#v", result)
	}
	if result.InvoiceID != common.BuildInvoiceID(result.Payment.ID) {
		t.Fatalf("invoice id = %q, want %q", result.InvoiceID, common.BuildInvoiceID(result.Payment.ID))
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
	if common.NormalizePaymentStatus(payment.Status) != "success" {
		t.Fatalf("payment status = %q, want success", common.NormalizePaymentStatus(payment.Status))
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
	if subscription.PaymentMethod != common.PaymentMethodTopup {
		t.Fatalf("subscription payment_method = %q, want %q", subscription.PaymentMethod, common.PaymentMethodTopup)
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
	if walletTransactions[0].Amount != 25 || walletTransactions[0].Type != common.WalletTransactionTypeTopup {
		t.Fatalf("first wallet transaction = %#v, want topup amount 25", walletTransactions[0])
	}
	if walletTransactions[1].Amount != -30 || walletTransactions[1].Type != common.WalletTransactionTypeSubscriptionDebit {
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
	if metadataPayload["payment_method"] != common.PaymentMethodTopup {
		t.Fatalf("metadata payment_method = %v, want %q", metadataPayload["payment_method"], common.PaymentMethodTopup)
	}
	if metadataPayload["wallet_amount"] != 30.0 {
		t.Fatalf("metadata wallet_amount = %v, want 30", metadataPayload["wallet_amount"])
	}
	if metadataPayload["topup_amount"] != 25.0 {
		t.Fatalf("metadata topup_amount = %v, want 25", metadataPayload["topup_amount"])
	}
}
