package payment

type CreatePaymentRequest struct {
	PlanID        string   `json:"plan_id" binding:"required"`
	TermMonths    int32    `json:"term_months" binding:"required"`
	PaymentMethod string   `json:"payment_method" binding:"required"`
	TopupAmount   *float64 `json:"topup_amount,omitempty"`
}

type TopupWalletRequest struct {
	Amount float64 `json:"amount" binding:"required"`
}
