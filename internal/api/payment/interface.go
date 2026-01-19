package payment

import "github.com/gin-gonic/gin"

// PaymentHandler defines the interface for payment operations
type PaymentHandler interface {
	CreatePayment(c *gin.Context)
}

// CreatePaymentRequest defines the payload for creating a payment
type CreatePaymentRequest struct {
	PlanID string  `json:"plan_id" binding:"required"`
	Amount float64 `json:"amount" binding:"required"`
}
