//go:build ignore
// +build ignore

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

const (
	adminWalletTransactionTypeTopup             = "topup"
	adminWalletTransactionTypeSubscriptionDebit = "subscription_debit"
	adminPaymentMethodWallet                    = "wallet"
	adminPaymentMethodTopup                     = "topup"
)

var adminAllowedTermMonths = map[int32]struct{}{
	1: {}, 3: {}, 6: {}, 12: {},
}

type AdminPaymentPayload struct {
	ID            string   `json:"id"`
	UserID        string   `json:"user_id"`
	PlanID        *string  `json:"plan_id,omitempty"`
	Amount        float64  `json:"amount"`
	Currency      string   `json:"currency"`
	Status        string   `json:"status"`
	Provider      string   `json:"provider"`
	TransactionID string   `json:"transaction_id,omitempty"`
	UserEmail     string   `json:"user_email,omitempty"`
	PlanName      string   `json:"plan_name,omitempty"`
	InvoiceID     string   `json:"invoice_id"`
	TermMonths    *int32   `json:"term_months,omitempty"`
	PaymentMethod *string  `json:"payment_method,omitempty"`
	ExpiresAt     *string  `json:"expires_at,omitempty"`
	WalletAmount  *float64 `json:"wallet_amount,omitempty"`
	TopupAmount   *float64 `json:"topup_amount,omitempty"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

type CreateAdminPaymentRequest struct {
	UserID        string   `json:"user_id" binding:"required"`
	PlanID        string   `json:"plan_id" binding:"required"`
	TermMonths    int32    `json:"term_months" binding:"required"`
	PaymentMethod string   `json:"payment_method" binding:"required"`
	TopupAmount   *float64 `json:"topup_amount,omitempty"`
}

type UpdateAdminPaymentRequest struct {
	Status string `json:"status" binding:"required"`
}

func normalizeAdminPaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case adminPaymentMethodWallet:
		return adminPaymentMethodWallet
	case adminPaymentMethodTopup:
		return adminPaymentMethodTopup
	default:
		return ""
	}
}

func normalizeAdminPaymentStatus(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "PENDING":
		return "PENDING"
	case "FAILED":
		return "FAILED"
	default:
		return "SUCCESS"
	}
}

func adminIsAllowedTermMonths(value int32) bool {
	_, ok := adminAllowedTermMonths[value]
	return ok
}

func (h *Handler) loadAdminPaymentPayload(ctx *gin.Context, payment model.Payment) (AdminPaymentPayload, error) {
	payload := AdminPaymentPayload{
		ID:            payment.ID,
		UserID:        payment.UserID,
		PlanID:        payment.PlanID,
		Amount:        payment.Amount,
		Currency:      strings.ToUpper(adminStringValue(payment.Currency)),
		Status:        normalizeAdminPaymentStatus(adminStringValue(payment.Status)),
		Provider:      strings.ToUpper(adminStringValue(payment.Provider)),
		TransactionID: adminStringValue(payment.TransactionID),
		InvoiceID:     adminInvoiceID(payment.ID),
		CreatedAt:     adminFormatTime(payment.CreatedAt),
		UpdatedAt:     adminFormatTimeValue(payment.UpdatedAt),
	}
	if payload.Currency == "" {
		payload.Currency = "USD"
	}

	var user model.User
	if err := h.db.WithContext(ctx.Request.Context()).Select("id, email").Where("id = ?", payment.UserID).First(&user).Error; err == nil {
		payload.UserEmail = user.Email
	}

	if payment.PlanID != nil && strings.TrimSpace(*payment.PlanID) != "" {
		var plan model.Plan
		if err := h.db.WithContext(ctx.Request.Context()).Where("id = ?", *payment.PlanID).First(&plan).Error; err == nil {
			payload.PlanName = plan.Name
		}
	}

	var subscription model.PlanSubscription
	if err := h.db.WithContext(ctx.Request.Context()).Where("payment_id = ?", payment.ID).Order("created_at DESC").First(&subscription).Error; err == nil {
		payload.TermMonths = &subscription.TermMonths
		method := subscription.PaymentMethod
		payload.PaymentMethod = &method
		expiresAt := subscription.ExpiresAt.UTC().Format(time.RFC3339)
		payload.ExpiresAt = &expiresAt
		payload.WalletAmount = &subscription.WalletAmount
		payload.TopupAmount = &subscription.TopupAmount
	}

	return payload, nil
}

func (h *Handler) adminLockUserForUpdate(ctx *gin.Context, tx *gorm.DB, userID string) (*model.User, error) {
	var user model.User
	if err := tx.WithContext(ctx.Request.Context()).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (h *Handler) adminCreateSubscriptionPayment(ctx *gin.Context, req CreateAdminPaymentRequest) (*model.Payment, *model.PlanSubscription, float64, error) {
	planID := strings.TrimSpace(req.PlanID)
	userID := strings.TrimSpace(req.UserID)
	paymentMethod := normalizeAdminPaymentMethod(req.PaymentMethod)
	if paymentMethod == "" {
		return nil, nil, 0, errors.New("Payment method must be wallet or topup")
	}
	if !adminIsAllowedTermMonths(req.TermMonths) {
		return nil, nil, 0, errors.New("Term months must be one of 1, 3, 6, or 12")
	}

	var planRecord model.Plan
	if err := h.db.WithContext(ctx.Request.Context()).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, 0, errors.New("Plan not found")
		}
		return nil, nil, 0, err
	}
	if !adminBoolValue(planRecord.IsActive, true) {
		return nil, nil, 0, errors.New("Plan is not active")
	}

	var user model.User
	if err := h.db.WithContext(ctx.Request.Context()).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, 0, errors.New("User not found")
		}
		return nil, nil, 0, err
	}

	totalAmount := planRecord.Price * float64(req.TermMonths)
	status := "SUCCESS"
	provider := "INTERNAL"
	currency := "USD"
	transactionID := adminTransactionID("sub")
	now := time.Now().UTC()
	payment := &model.Payment{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		PlanID:        &planRecord.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &status,
		Provider:      &provider,
		TransactionID: &transactionID,
	}

	var subscription *model.PlanSubscription
	var walletBalance float64
	err := h.db.WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if _, err := h.adminLockUserForUpdate(ctx, tx, user.ID); err != nil {
			return err
		}

		var currentSubscription model.PlanSubscription
		hasCurrentSubscription := false
		if err := tx.Where("user_id = ?", user.ID).Order("created_at DESC").First(&currentSubscription).Error; err == nil {
			hasCurrentSubscription = true
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		baseExpiry := now
		if hasCurrentSubscription && currentSubscription.ExpiresAt.After(baseExpiry) {
			baseExpiry = currentSubscription.ExpiresAt.UTC()
		}
		newExpiry := baseExpiry.AddDate(0, int(req.TermMonths), 0)

		currentWalletBalance, err := model.GetWalletBalance(ctx.Request.Context(), tx, user.ID)
		if err != nil {
			return err
		}
		shortfall := totalAmount - currentWalletBalance
		if shortfall < 0 {
			shortfall = 0
		}
		if paymentMethod == adminPaymentMethodWallet && shortfall > 0 {
			return fmt.Errorf("Insufficient wallet balance")
		}

		topupAmount := 0.0
		if paymentMethod == adminPaymentMethodTopup {
			if req.TopupAmount == nil {
				return fmt.Errorf("Top-up amount is required when payment method is topup")
			}
			topupAmount = *req.TopupAmount
			if topupAmount <= 0 {
				return fmt.Errorf("Top-up amount must be greater than 0")
			}
			if topupAmount < shortfall {
				return fmt.Errorf("Top-up amount must be greater than or equal to the required shortfall")
			}
		}

		if err := tx.Create(payment).Error; err != nil {
			return err
		}

		if paymentMethod == adminPaymentMethodTopup {
			topupTransaction := &model.WalletTransaction{
				ID:         uuid.New().String(),
				UserID:     user.ID,
				Type:       adminWalletTransactionTypeTopup,
				Amount:     topupAmount,
				Currency:   model.StringPtr(currency),
				Note:       model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", planRecord.Name, req.TermMonths)),
				PaymentID:  &payment.ID,
				PlanID:     &planRecord.ID,
				TermMonths: &req.TermMonths,
			}
			if err := tx.Create(topupTransaction).Error; err != nil {
				return err
			}
		}

		debitTransaction := &model.WalletTransaction{
			ID:         uuid.New().String(),
			UserID:     user.ID,
			Type:       adminWalletTransactionTypeSubscriptionDebit,
			Amount:     -totalAmount,
			Currency:   model.StringPtr(currency),
			Note:       model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", planRecord.Name, req.TermMonths)),
			PaymentID:  &payment.ID,
			PlanID:     &planRecord.ID,
			TermMonths: &req.TermMonths,
		}
		if err := tx.Create(debitTransaction).Error; err != nil {
			return err
		}

		subscription = &model.PlanSubscription{
			ID:            uuid.New().String(),
			UserID:        user.ID,
			PaymentID:     payment.ID,
			PlanID:        planRecord.ID,
			TermMonths:    req.TermMonths,
			PaymentMethod: paymentMethod,
			WalletAmount:  totalAmount,
			TopupAmount:   topupAmount,
			StartedAt:     now,
			ExpiresAt:     newExpiry,
		}
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Update("plan_id", planRecord.ID).Error; err != nil {
			return err
		}

		notification := &model.Notification{
			ID:       uuid.New().String(),
			UserID:   user.ID,
			Type:     "billing.subscription",
			Title:    "Subscription activated",
			Message:  fmt.Sprintf("Your subscription to %s is active until %s.", planRecord.Name, subscription.ExpiresAt.UTC().Format("2006-01-02")),
			Metadata: model.StringPtr("{}"),
		}
		if err := tx.Create(notification).Error; err != nil {
			return err
		}

		walletBalance, err = model.GetWalletBalance(ctx.Request.Context(), tx, user.ID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}
	return payment, subscription, walletBalance, nil
}

// @Summary      List All Payments
// @Description  Get paginated list of all payments across users (admin only)
// @Tags         admin
// @Produce      json
// @Param        page query int false "Page" default(1)
// @Param        limit query int false "Limit" default(20)
// @Param        user_id query string false "Filter by user ID"
// @Param        status query string false "Filter by status"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Router       /admin/payments [get]
// @Security     BearerAuth
func (h *Handler) ListPayments(c *gin.Context) {
	ctx := c.Request.Context()
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	userID := strings.TrimSpace(c.Query("user_id"))
	status := strings.TrimSpace(c.Query("status"))

	db := h.db.WithContext(ctx).Model(&model.Payment{})
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if status != "" {
		db = db.Where("UPPER(status) = ?", strings.ToUpper(status))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to list payments")
		return
	}

	var payments []model.Payment
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&payments).Error; err != nil {
		h.logger.Error("Failed to list payments", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list payments")
		return
	}

	result := make([]AdminPaymentPayload, 0, len(payments))
	for _, p := range payments {
		payload, err := h.loadAdminPaymentPayload(c, p)
		if err != nil {
			response.Error(c, http.StatusInternalServerError, "Failed to list payments")
			return
		}
		result = append(result, payload)
	}

	response.Success(c, gin.H{
		"payments": result,
		"total":    total,
		"page":     page,
		"limit":    limit,
	})
}

// @Summary      Get Payment Detail
// @Description  Get payment detail (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Payment ID"
// @Success      200  {object}  response.Response
// @Router       /admin/payments/{id} [get]
// @Security     BearerAuth
func (h *Handler) GetPayment(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Payment not found")
		return
	}

	var payment model.Payment
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&payment).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Payment not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to get payment")
		return
	}

	payload, err := h.loadAdminPaymentPayload(c, payment)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to get payment")
		return
	}

	response.Success(c, gin.H{"payment": payload})
}

// @Summary      Create Payment
// @Description  Create a model subscription charge for a user (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request body CreateAdminPaymentRequest true "Payment payload"
// @Success      201  {object}  response.Response
// @Router       /admin/payments [post]
// @Security     BearerAuth
func (h *Handler) CreatePayment(c *gin.Context) {
	var req CreateAdminPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	payment, subscription, walletBalance, err := h.adminCreateSubscriptionPayment(c, req)
	if err != nil {
		switch err.Error() {
		case "User not found", "Plan not found", "Plan is not active", "Payment method must be wallet or topup", "Term months must be one of 1, 3, 6, or 12", "Insufficient wallet balance", "Top-up amount is required when payment method is topup", "Top-up amount must be greater than 0", "Top-up amount must be greater than or equal to the required shortfall":
			response.Error(c, http.StatusBadRequest, err.Error())
			return
		default:
			h.logger.Error("Failed to create admin payment", "error", err)
			response.Error(c, http.StatusInternalServerError, "Failed to create payment")
			return
		}
	}

	payload, err := h.loadAdminPaymentPayload(c, *payment)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to create payment")
		return
	}

	response.Created(c, gin.H{
		"payment":        payload,
		"subscription":   subscription,
		"wallet_balance": walletBalance,
		"invoice_id":     adminInvoiceID(payment.ID),
	})
}

// @Summary      Update Payment
// @Description  Update payment status safely without hard delete (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "Payment ID"
// @Param        request body UpdateAdminPaymentRequest true "Payment update payload"
// @Success      200  {object}  response.Response
// @Router       /admin/payments/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdatePayment(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Payment not found")
		return
	}

	var req UpdateAdminPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	newStatus := normalizeAdminPaymentStatus(req.Status)
	var payment model.Payment
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&payment).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Payment not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to update payment")
		return
	}

	currentStatus := normalizeAdminPaymentStatus(adminStringValue(payment.Status))
	if currentStatus != newStatus {
		if (currentStatus == "FAILED" || currentStatus == "PENDING") && newStatus == "SUCCESS" {
			response.Error(c, http.StatusBadRequest, "Cannot transition payment to SUCCESS from admin update; recreate through the payment flow instead")
			return
		}
		payment.Status = &newStatus
		if err := h.db.WithContext(c.Request.Context()).Save(&payment).Error; err != nil {
			h.logger.Error("Failed to update payment", "error", err)
			response.Error(c, http.StatusInternalServerError, "Failed to update payment")
			return
		}
	}

	payload, err := h.loadAdminPaymentPayload(c, payment)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to update payment")
		return
	}

	response.Success(c, gin.H{"payment": payload})
}
