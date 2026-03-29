package service

import (
	"fmt"
	"time"

	"stream.api/internal/database/model"
)

func latestNotificationForPayment(paymentRecord *model.Payment, subscription *model.PlanSubscription, plan *model.Plan, invoiceID string) *model.Notification {
	if paymentRecord == nil || subscription == nil || plan == nil {
		return nil
	}
	return &model.Notification{
		ID:      "",
		UserID:  paymentRecord.UserID,
		Type:    "billing.subscription",
		Title:   "Subscription activated",
		Message: fmt.Sprintf("Your subscription to %s is active until %s.", plan.Name, subscription.ExpiresAt.UTC().Format("2006-01-02")),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
			"payment_id":      paymentRecord.ID,
			"invoice_id":      invoiceID,
			"plan_id":         plan.ID,
			"term_months":     subscription.TermMonths,
			"payment_method":  subscription.PaymentMethod,
			"wallet_amount":   subscription.WalletAmount,
			"topup_amount":    subscription.TopupAmount,
			"plan_expires_at": subscription.ExpiresAt.UTC().Format(time.RFC3339),
		})),
	}
}
