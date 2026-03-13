package payment

import "time"

type PaymentHistoryItem struct {
	ID            string     `json:"id"`
	Amount        float64    `json:"amount"`
	Currency      string     `json:"currency"`
	Status        string     `json:"status"`
	PlanID        *string    `json:"plan_id,omitempty"`
	PlanName      *string    `json:"plan_name,omitempty"`
	InvoiceID     string     `json:"invoice_id"`
	Kind          string     `json:"kind"`
	TermMonths    *int32     `json:"term_months,omitempty"`
	PaymentMethod *string    `json:"payment_method,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
}
