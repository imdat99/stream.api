package payment

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	cfg    *config.Config
}

func NewHandler(l logger.Logger, cfg *config.Config) PaymentHandler {
	return &Handler{
		logger: l,
		cfg:    cfg,
	}
}

// @Summary      Create Payment
// @Description  Create a new payment
// @Tags         payment
// @Accept       json
// @Produce      json
// @Param        request body CreatePaymentRequest true "Payment Info"
// @Success      201  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /payments [post]
// @Security     BearerAuth
func (h *Handler) CreatePayment(c *gin.Context) {
	var req CreatePaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// In a real scenario, we would contact Stripe/PayPal here to create a session
	// For now, we just create a "PENDING" payment record.

	status := "PENDING"
	provider := "STRIPE"

	payment := &model.Payment{
		ID:       uuid.New().String(),
		UserID:   userID,
		PlanID:   &req.PlanID,
		Amount:   req.Amount,
		Status:   &status,
		Provider: &provider, // Defaulting to Stripe for this example
	}

	p := query.Payment
	if err := p.WithContext(c.Request.Context()).Create(payment); err != nil {
		h.logger.Error("Failed to create payment", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create payment")
		return
	}

	response.Created(c, gin.H{"payment": payment, "message": "Payment initiated"})
}
