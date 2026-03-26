package payments

import "stream.api/internal/database/model"

type CreatePaymentCommand struct {
	UserID        string
	PlanID        string
	TermMonths    int32
	PaymentMethod string
	TopupAmount   *float64
}

type CreatePaymentResult struct {
	Payment       *model.Payment
	Subscription  *model.PlanSubscription
	WalletBalance float64
	InvoiceID     string
	Message       string
}

type PaymentHistoryQuery struct {
	UserID string
	Page   int32
	Limit  int32
}

type PaymentHistoryItem struct {
	ID            string
	Amount        float64
	Currency      string
	Status        string
	PlanID        *string
	PlanName      *string
	InvoiceID     string
	Kind          string
	TermMonths    *int32
	PaymentMethod *string
	ExpiresAt     *string
	CreatedAt     *string
}

type PaymentHistoryResult struct {
	Items   []PaymentHistoryItem
	Total   int64
	Page    int32
	Limit   int32
	HasPrev bool
	HasNext bool
}

type TopupWalletCommand struct {
	UserID string
	Amount float64
}

type TopupWalletResult struct {
	WalletTransaction *model.WalletTransaction
	WalletBalance     float64
	InvoiceID         string
}

type DownloadInvoiceQuery struct {
	UserID string
	ID     string
}

type DownloadInvoiceResult struct {
	Filename    string
	ContentType string
	Content     string
}

type ListAdminPaymentsQuery struct {
	Page         int32
	Limit        int32
	UserID       string
	StatusFilter string
}

type AdminPaymentView struct {
	ID            string
	UserID        string
	PlanID        *string
	Amount        float64
	Currency      string
	Status        string
	Provider      string
	TransactionID *string
	InvoiceID     string
	CreatedAt     *string
	UpdatedAt     *string
	UserEmail     *string
	PlanName      *string
	TermMonths    *int32
	PaymentMethod *string
	ExpiresAt     *string
	WalletAmount  *float64
	TopupAmount   *float64
}

type ListAdminPaymentsResult struct {
	Items []AdminPaymentView
	Total int64
	Page  int32
	Limit int32
}

type GetAdminPaymentQuery struct {
	ID string
}

type CreateAdminPaymentCommand struct {
	UserID        string
	PlanID        string
	TermMonths    int32
	PaymentMethod string
	TopupAmount   *float64
}

type CreateAdminPaymentResult struct {
	Payment       AdminPaymentView
	Subscription  *model.PlanSubscription
	WalletBalance float64
	InvoiceID     string
}

type UpdateAdminPaymentCommand struct {
	ID        string
	NewStatus string
}

type PaymentValidationError struct {
	GRPCCode int
	HTTPCode int
	Message  string
	Data     map[string]any
}
