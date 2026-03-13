//go:build ignore
// +build ignore

package payment

import "github.com/gin-gonic/gin"

// PaymentHandler defines the interface for payment operations
type PaymentHandler interface {
	CreatePayment(c *gin.Context)
	ListPaymentHistory(c *gin.Context)
	TopupWallet(c *gin.Context)
	DownloadInvoice(c *gin.Context)
}

// CreatePaymentRequest defines the payload for creating a payment
type CreatePaymentRequest struct {
	PlanID        string   `json:"plan_id" binding:"required"`
	TermMonths    int32    `json:"term_months" binding:"required"`
	PaymentMethod string   `json:"payment_method" binding:"required"`
	TopupAmount   *float64 `json:"topup_amount,omitempty"`
}

type TopupWalletRequest struct {
	Amount float64 `json:"amount" binding:"required"`
}
