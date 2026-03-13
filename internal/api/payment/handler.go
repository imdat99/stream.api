//go:build ignore
// +build ignore

package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

const (
	walletTransactionTypeTopup             = "topup"
	walletTransactionTypeSubscriptionDebit = "subscription_debit"
	paymentMethodWallet                    = "wallet"
	paymentMethodTopup                     = "topup"
	paymentKindSubscription                = "subscription"
	paymentKindWalletTopup                 = "wallet_topup"
)

var allowedTermMonths = map[int32]struct{}{
	1:  {},
	3:  {},
	6:  {},
	12: {},
}

type Handler struct {
	logger logger.Logger
	cfg    *config.Config
	db     *gorm.DB
}

type paymentRow struct {
	ID            string     `gorm:"column:id"`
	Amount        float64    `gorm:"column:amount"`
	Currency      *string    `gorm:"column:currency"`
	Status        *string    `gorm:"column:status"`
	PlanID        *string    `gorm:"column:plan_id"`
	PlanName      *string    `gorm:"column:plan_name"`
	TermMonths    *int32     `gorm:"column:term_months"`
	PaymentMethod *string    `gorm:"column:payment_method"`
	ExpiresAt     *time.Time `gorm:"column:expires_at"`
	CreatedAt     *time.Time `gorm:"column:created_at"`
}

type paymentInvoiceDetails struct {
	PlanName      string
	TermMonths    *int32
	PaymentMethod string
	ExpiresAt     *time.Time
	WalletAmount  float64
	TopupAmount   float64
}

type paymentError struct {
	Code    int
	Message string
	Data    interface{}
}

func (e *paymentError) Error() string {
	return e.Message
}

func NewHandler(l logger.Logger, cfg *config.Config, db *gorm.DB) PaymentHandler {
	return &Handler{
		logger: l,
		cfg:    cfg,
		db:     db,
	}
}

// @Summary      Create Payment
// @Description  Create a new payment for buying or renewing a plan
// @Tags         payment
// @Accept       json
// @Produce      json
// @Param        request body CreatePaymentRequest true "Payment Info"
// @Success      201  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
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

	planID := strings.TrimSpace(req.PlanID)
	if planID == "" {
		response.Error(c, http.StatusBadRequest, "Plan ID is required")
		return
	}
	if !isAllowedTermMonths(req.TermMonths) {
		response.Error(c, http.StatusBadRequest, "Term months must be one of 1, 3, 6, or 12")
		return
	}

	paymentMethod := normalizePaymentMethod(req.PaymentMethod)
	if paymentMethod == "" {
		response.Error(c, http.StatusBadRequest, "Payment method must be wallet or topup")
		return
	}

	ctx := c.Request.Context()
	var planRecord model.Plan
	if err := h.db.WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Plan not found")
			return
		}
		h.logger.Error("Failed to load plan", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create payment")
		return
	}

	if planRecord.IsActive == nil || !*planRecord.IsActive {
		response.Error(c, http.StatusBadRequest, "Plan is not active")
		return
	}

	totalAmount := planRecord.Price * float64(req.TermMonths)
	if totalAmount < 0 {
		response.Error(c, http.StatusBadRequest, "Amount must be greater than or equal to 0")
		return
	}

	status := "SUCCESS"
	provider := "INTERNAL"
	currency := normalizeCurrency(nil)
	transactionID := buildTransactionID("sub")
	now := time.Now().UTC()

	payment := &model.Payment{
		ID:            uuid.New().String(),
		UserID:        userID,
		PlanID:        &planRecord.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &status,
		Provider:      &provider,
		TransactionID: &transactionID,
	}

	invoiceID := buildInvoiceID(payment.ID)
	var subscription *model.PlanSubscription
	var walletBalance float64

	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(ctx, tx, userID); err != nil {
			return err
		}

		currentSubscription, err := model.GetLatestPlanSubscription(ctx, tx, userID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		baseExpiry := now
		if currentSubscription != nil && currentSubscription.ExpiresAt.After(baseExpiry) {
			baseExpiry = currentSubscription.ExpiresAt.UTC()
		}
		newExpiry := baseExpiry.AddDate(0, int(req.TermMonths), 0)

		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, userID)
		if err != nil {
			return err
		}
		shortfall := maxFloat(totalAmount-currentWalletBalance, 0)

		if paymentMethod == paymentMethodWallet && shortfall > 0 {
			return &paymentError{
				Code:    http.StatusBadRequest,
				Message: "Insufficient wallet balance",
				Data: gin.H{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
				},
			}
		}

		topupAmount := 0.0
		if paymentMethod == paymentMethodTopup {
			if req.TopupAmount == nil {
				return &paymentError{
					Code:    http.StatusBadRequest,
					Message: "Top-up amount is required when payment method is topup",
					Data: gin.H{
						"payment_method": paymentMethod,
						"wallet_balance": currentWalletBalance,
						"total_amount":   totalAmount,
						"shortfall":      shortfall,
					},
				}
			}

			topupAmount = maxFloat(*req.TopupAmount, 0)
			if topupAmount <= 0 {
				return &paymentError{
					Code:    http.StatusBadRequest,
					Message: "Top-up amount must be greater than 0",
					Data: gin.H{
						"payment_method": paymentMethod,
						"wallet_balance": currentWalletBalance,
						"total_amount":   totalAmount,
						"shortfall":      shortfall,
					},
				}
			}
			if topupAmount < shortfall {
				return &paymentError{
					Code:    http.StatusBadRequest,
					Message: "Top-up amount must be greater than or equal to the required shortfall",
					Data: gin.H{
						"payment_method": paymentMethod,
						"wallet_balance": currentWalletBalance,
						"total_amount":   totalAmount,
						"shortfall":      shortfall,
						"topup_amount":   topupAmount,
					},
				}
			}
		}

		if err := tx.Create(payment).Error; err != nil {
			return err
		}

		walletUsedAmount := totalAmount

		if paymentMethod == paymentMethodTopup {
			topupTransaction := &model.WalletTransaction{
				ID:         uuid.New().String(),
				UserID:     userID,
				Type:       walletTransactionTypeTopup,
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
			UserID:     userID,
			Type:       walletTransactionTypeSubscriptionDebit,
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
			UserID:        userID,
			PaymentID:     payment.ID,
			PlanID:        planRecord.ID,
			TermMonths:    req.TermMonths,
			PaymentMethod: paymentMethod,
			WalletAmount:  walletUsedAmount,
			TopupAmount:   topupAmount,
			StartedAt:     now,
			ExpiresAt:     newExpiry,
		}
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).
			Where("id = ?", userID).
			Update("plan_id", planRecord.ID).Error; err != nil {
			return err
		}

		notification := buildSubscriptionNotification(userID, payment.ID, invoiceID, &planRecord, subscription)
		if err := tx.Create(notification).Error; err != nil {
			return err
		}

		walletBalance, err = model.GetWalletBalance(ctx, tx, userID)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		var paymentErr *paymentError
		if errors.As(err, &paymentErr) {
			c.AbortWithStatusJSON(paymentErr.Code, response.Response{
				Code:    paymentErr.Code,
				Message: paymentErr.Message,
				Data:    paymentErr.Data,
			})
			return
		}

		h.logger.Error("Failed to create payment", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create payment")
		return
	}

	response.Created(c, gin.H{
		"payment":        payment,
		"subscription":   subscription,
		"wallet_balance": walletBalance,
		"invoice_id":     invoiceID,
		"message":        "Payment completed successfully",
	})
}

// @Summary      List Payment History
// @Description  Get payment history for the current user
// @Tags         payment
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /payments/history [get]
// @Security     BearerAuth
func (h *Handler) ListPaymentHistory(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var rows []paymentRow
	if err := h.db.WithContext(c.Request.Context()).
		Table("payment AS p").
		Select("p.id, p.amount, p.currency, p.status, p.plan_id, pl.name AS plan_name, ps.term_months, ps.payment_method, ps.expires_at, p.created_at").
		Joins("LEFT JOIN plan AS pl ON pl.id = p.plan_id").
		Joins("LEFT JOIN plan_subscriptions AS ps ON ps.payment_id = p.id").
		Where("p.user_id = ?", userID).
		Order("p.created_at DESC").
		Scan(&rows).Error; err != nil {
		h.logger.Error("Failed to fetch payment history", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch payment history")
		return
	}

	items := make([]PaymentHistoryItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, PaymentHistoryItem{
			ID:            row.ID,
			Amount:        row.Amount,
			Currency:      normalizeCurrency(row.Currency),
			Status:        normalizePaymentStatus(row.Status),
			PlanID:        row.PlanID,
			PlanName:      row.PlanName,
			InvoiceID:     buildInvoiceID(row.ID),
			Kind:          paymentKindSubscription,
			TermMonths:    row.TermMonths,
			PaymentMethod: normalizeOptionalPaymentMethod(row.PaymentMethod),
			ExpiresAt:     row.ExpiresAt,
			CreatedAt:     row.CreatedAt,
		})
	}

	var topups []model.WalletTransaction
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ? AND type = ? AND payment_id IS NULL", userID, walletTransactionTypeTopup).
		Order("created_at DESC").
		Find(&topups).Error; err != nil {
		h.logger.Error("Failed to fetch wallet topups", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch payment history")
		return
	}

	for _, topup := range topups {
		createdAt := topup.CreatedAt
		items = append(items, PaymentHistoryItem{
			ID:        topup.ID,
			Amount:    topup.Amount,
			Currency:  normalizeCurrency(topup.Currency),
			Status:    "success",
			InvoiceID: buildInvoiceID(topup.ID),
			Kind:      paymentKindWalletTopup,
			CreatedAt: createdAt,
		})
	}

	sortPaymentHistory(items)
	response.Success(c, gin.H{"payments": items})
}

// @Summary      Top Up Wallet
// @Description  Add funds to wallet balance for the current user
// @Tags         payment
// @Accept       json
// @Produce      json
// @Param        request body TopupWalletRequest true "Topup Info"
// @Success      201  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /wallet/topups [post]
// @Security     BearerAuth
func (h *Handler) TopupWallet(c *gin.Context) {
	var req TopupWalletRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	amount := req.Amount
	if amount < 1 {
		response.Error(c, http.StatusBadRequest, "Amount must be at least 1")
		return
	}

	transaction := &model.WalletTransaction{
		ID:       uuid.New().String(),
		UserID:   userID,
		Type:     walletTransactionTypeTopup,
		Amount:   amount,
		Currency: model.StringPtr("USD"),
		Note:     model.StringPtr(fmt.Sprintf("Wallet top-up of %.2f USD", amount)),
	}

	notification := &model.Notification{
		ID:      uuid.New().String(),
		UserID:  userID,
		Type:    "billing.topup",
		Title:   "Wallet credited",
		Message: fmt.Sprintf("Your wallet has been credited with %.2f USD.", amount),
		Metadata: model.StringPtr(mustMarshalJSON(gin.H{
			"wallet_transaction_id": transaction.ID,
			"invoice_id":            buildInvoiceID(transaction.ID),
		})),
	}

	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(c.Request.Context(), tx, userID); err != nil {
			return err
		}
		if err := tx.Create(transaction).Error; err != nil {
			return err
		}
		if err := tx.Create(notification).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.logger.Error("Failed to top up wallet", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to top up wallet")
		return
	}

	balance, err := model.GetWalletBalance(c.Request.Context(), h.db, userID)
	if err != nil {
		h.logger.Error("Failed to calculate wallet balance", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to top up wallet")
		return
	}

	response.Created(c, gin.H{
		"wallet_transaction": transaction,
		"wallet_balance":     balance,
		"invoice_id":         buildInvoiceID(transaction.ID),
	})
}

// @Summary      Download Invoice
// @Description  Download invoice text for a payment or wallet top-up
// @Tags         payment
// @Produce      plain
// @Param        id path string true "Payment ID"
// @Success      200  {string}  string
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /payments/{id}/invoice [get]
// @Security     BearerAuth
func (h *Handler) DownloadInvoice(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Invoice not found")
		return
	}

	ctx := c.Request.Context()
	paymentRecord, err := query.Payment.WithContext(ctx).
		Where(query.Payment.ID.Eq(id), query.Payment.UserID.Eq(userID)).
		First()
	if err == nil {
		invoiceText, filename, buildErr := h.buildPaymentInvoice(ctx, paymentRecord)
		if buildErr != nil {
			h.logger.Error("Failed to build payment invoice", "error", buildErr)
			response.Error(c, http.StatusInternalServerError, "Failed to download invoice")
			return
		}
		serveInvoiceText(c, filename, invoiceText)
		return
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		h.logger.Error("Failed to load payment invoice", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to download invoice")
		return
	}

	var topup model.WalletTransaction
	if err := h.db.WithContext(ctx).
		Where("id = ? AND user_id = ? AND type = ? AND payment_id IS NULL", id, userID, walletTransactionTypeTopup).
		First(&topup).Error; err == nil {
		invoiceText := buildTopupInvoice(&topup)
		serveInvoiceText(c, buildInvoiceFilename(topup.ID), invoiceText)
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		h.logger.Error("Failed to load topup invoice", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to download invoice")
		return
	}

	response.Error(c, http.StatusNotFound, "Invoice not found")
}

func normalizePaymentStatus(status *string) string {
	value := strings.ToLower(strings.TrimSpace(stringValue(status)))
	switch value {
	case "success", "succeeded", "paid":
		return "success"
	case "failed", "error", "canceled", "cancelled":
		return "failed"
	case "pending", "processing":
		return "pending"
	default:
		if value == "" {
			return "success"
		}
		return value
	}
}

func normalizeCurrency(currency *string) string {
	value := strings.ToUpper(strings.TrimSpace(stringValue(currency)))
	if value == "" {
		return "USD"
	}
	return value
}

func normalizePaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case paymentMethodWallet:
		return paymentMethodWallet
	case paymentMethodTopup:
		return paymentMethodTopup
	default:
		return ""
	}
}

func normalizeOptionalPaymentMethod(value *string) *string {
	normalized := normalizePaymentMethod(stringValue(value))
	if normalized == "" {
		return nil
	}
	return &normalized
}

func buildInvoiceID(id string) string {
	trimmed := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	return "INV-" + strings.ToUpper(trimmed)
}

func buildTransactionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func buildInvoiceFilename(id string) string {
	return fmt.Sprintf("invoice-%s.txt", id)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sortPaymentHistory(items []PaymentHistoryItem) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			left := time.Time{}
			right := time.Time{}
			if items[i].CreatedAt != nil {
				left = *items[i].CreatedAt
			}
			if items[j].CreatedAt != nil {
				right = *items[j].CreatedAt
			}
			if right.After(left) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func serveInvoiceText(c *gin.Context, filename string, content string) {
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.String(http.StatusOK, content)
}

func (h *Handler) buildPaymentInvoice(ctx context.Context, paymentRecord *model.Payment) (string, string, error) {
	details, err := h.loadPaymentInvoiceDetails(ctx, paymentRecord)
	if err != nil {
		return "", "", err
	}

	createdAt := formatOptionalTimestamp(paymentRecord.CreatedAt)
	lines := []string{
		"Stream API Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(paymentRecord.ID)),
		fmt.Sprintf("Payment ID: %s", paymentRecord.ID),
		fmt.Sprintf("User ID: %s", paymentRecord.UserID),
		fmt.Sprintf("Plan: %s", details.PlanName),
		fmt.Sprintf("Amount: %.2f %s", paymentRecord.Amount, normalizeCurrency(paymentRecord.Currency)),
		fmt.Sprintf("Status: %s", strings.ToUpper(normalizePaymentStatus(paymentRecord.Status))),
		fmt.Sprintf("Provider: %s", strings.ToUpper(stringValue(paymentRecord.Provider))),
		fmt.Sprintf("Payment Method: %s", strings.ToUpper(details.PaymentMethod)),
		fmt.Sprintf("Transaction ID: %s", stringValue(paymentRecord.TransactionID)),
	}

	if details.TermMonths != nil {
		lines = append(lines, fmt.Sprintf("Term: %d month(s)", *details.TermMonths))
	}
	if details.ExpiresAt != nil {
		lines = append(lines, fmt.Sprintf("Valid Until: %s", details.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	if details.WalletAmount > 0 {
		lines = append(lines, fmt.Sprintf("Wallet Applied: %.2f %s", details.WalletAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	if details.TopupAmount > 0 {
		lines = append(lines, fmt.Sprintf("Top-up Added: %.2f %s", details.TopupAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	lines = append(lines, fmt.Sprintf("Created At: %s", createdAt))

	return strings.Join(lines, "\n"), buildInvoiceFilename(paymentRecord.ID), nil
}

func buildTopupInvoice(transaction *model.WalletTransaction) string {
	createdAt := formatOptionalTimestamp(transaction.CreatedAt)
	return strings.Join([]string{
		"Stream API Wallet Top-up Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(transaction.ID)),
		fmt.Sprintf("Wallet Transaction ID: %s", transaction.ID),
		fmt.Sprintf("User ID: %s", transaction.UserID),
		fmt.Sprintf("Amount: %.2f %s", transaction.Amount, normalizeCurrency(transaction.Currency)),
		"Status: SUCCESS",
		fmt.Sprintf("Type: %s", strings.ToUpper(transaction.Type)),
		fmt.Sprintf("Note: %s", model.StringValue(transaction.Note)),
		fmt.Sprintf("Created At: %s", createdAt),
	}, "\n")
}

func (h *Handler) loadPaymentInvoiceDetails(ctx context.Context, paymentRecord *model.Payment) (*paymentInvoiceDetails, error) {
	details := &paymentInvoiceDetails{
		PlanName:      "Unknown plan",
		PaymentMethod: paymentMethodWallet,
	}

	if paymentRecord.PlanID != nil && strings.TrimSpace(*paymentRecord.PlanID) != "" {
		var planRecord model.Plan
		if err := h.db.WithContext(ctx).Where("id = ?", *paymentRecord.PlanID).First(&planRecord).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
		} else {
			details.PlanName = planRecord.Name
		}
	}

	var subscription model.PlanSubscription
	if err := h.db.WithContext(ctx).
		Where("payment_id = ?", paymentRecord.ID).
		Order("created_at DESC").
		First(&subscription).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return details, nil
	}

	details.TermMonths = &subscription.TermMonths
	details.PaymentMethod = normalizePaymentMethod(subscription.PaymentMethod)
	if details.PaymentMethod == "" {
		details.PaymentMethod = paymentMethodWallet
	}
	details.ExpiresAt = &subscription.ExpiresAt
	details.WalletAmount = subscription.WalletAmount
	details.TopupAmount = subscription.TopupAmount

	return details, nil
}

func buildSubscriptionNotification(userID string, paymentID string, invoiceID string, planRecord *model.Plan, subscription *model.PlanSubscription) *model.Notification {
	return &model.Notification{
		ID:      uuid.New().String(),
		UserID:  userID,
		Type:    "billing.subscription",
		Title:   "Subscription activated",
		Message: fmt.Sprintf("Your subscription to %s is active until %s.", planRecord.Name, subscription.ExpiresAt.UTC().Format("2006-01-02")),
		Metadata: model.StringPtr(mustMarshalJSON(gin.H{
			"payment_id":      paymentID,
			"invoice_id":      invoiceID,
			"plan_id":         planRecord.ID,
			"term_months":     subscription.TermMonths,
			"payment_method":  subscription.PaymentMethod,
			"wallet_amount":   subscription.WalletAmount,
			"topup_amount":    subscription.TopupAmount,
			"plan_expires_at": subscription.ExpiresAt.UTC().Format(time.RFC3339),
		})),
	}
}

func isAllowedTermMonths(value int32) bool {
	_, ok := allowedTermMonths[value]
	return ok
}

func lockUserForUpdate(ctx context.Context, tx *gorm.DB, userID string) (*model.User, error) {
	var user model.User
	if err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", userID).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func maxFloat(left float64, right float64) float64 {
	if left > right {
		return left
	}
	return right
}

func formatOptionalTimestamp(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func mustMarshalJSON(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
