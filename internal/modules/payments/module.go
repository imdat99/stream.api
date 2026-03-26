package payments

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/internal/modules/common"
)

type ExecutionInput struct {
	UserID        string
	Plan          *model.Plan
	TermMonths    int32
	PaymentMethod string
	TopupAmount   *float64
}

type ExecutionResult struct {
	Payment       *model.Payment
	Subscription  *model.PlanSubscription
	WalletBalance float64
	InvoiceID     string
}

type InvoiceDetails struct {
	PlanName      string
	TermMonths    *int32
	PaymentMethod string
	ExpiresAt     *time.Time
	WalletAmount  float64
	TopupAmount   float64
}

type ReferralRewardResult struct {
	Granted bool
	Amount  float64
}

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) CreatePayment(ctx context.Context, cmd CreatePaymentCommand) (*CreatePaymentResult, error) {
	planRecord, err := m.LoadPaymentPlanForUser(ctx, cmd.PlanID)
	if err != nil {
		return nil, err
	}
	resultValue, err := m.ExecutePaymentFlow(ctx, ExecutionInput{
		UserID:        cmd.UserID,
		Plan:          planRecord,
		TermMonths:    cmd.TermMonths,
		PaymentMethod: cmd.PaymentMethod,
		TopupAmount:   cmd.TopupAmount,
	})
	if err != nil {
		return nil, err
	}
	return &CreatePaymentResult{
		Payment:       resultValue.Payment,
		Subscription:  resultValue.Subscription,
		WalletBalance: resultValue.WalletBalance,
		InvoiceID:     resultValue.InvoiceID,
		Message:       "Payment completed successfully",
	}, nil
}

func (m *Module) ListPaymentHistory(ctx context.Context, queryValue PaymentHistoryQuery) (*PaymentHistoryResult, error) {
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)

	type paymentHistoryRow struct {
		ID            string     `gorm:"column:id"`
		Amount        float64    `gorm:"column:amount"`
		Currency      *string    `gorm:"column:currency"`
		Status        *string    `gorm:"column:status"`
		PlanID        *string    `gorm:"column:plan_id"`
		PlanName      *string    `gorm:"column:plan_name"`
		InvoiceID     string     `gorm:"column:invoice_id"`
		Kind          string     `gorm:"column:kind"`
		TermMonths    *int32     `gorm:"column:term_months"`
		PaymentMethod *string    `gorm:"column:payment_method"`
		ExpiresAt     *time.Time `gorm:"column:expires_at"`
		CreatedAt     *time.Time `gorm:"column:created_at"`
	}

	baseQuery := `
		WITH history AS (
			SELECT
				p.id AS id,
				p.amount AS amount,
				p.currency AS currency,
				p.status AS status,
				p.plan_id AS plan_id,
				pl.name AS plan_name,
				p.id AS invoice_id,
				? AS kind,
				ps.term_months AS term_months,
				ps.payment_method AS payment_method,
				ps.expires_at AS expires_at,
				p.created_at AS created_at
			FROM payment AS p
			LEFT JOIN plan AS pl ON pl.id = p.plan_id
			LEFT JOIN plan_subscriptions AS ps ON ps.payment_id = p.id
			WHERE p.user_id = ?
			UNION ALL
			SELECT
				wt.id AS id,
				wt.amount AS amount,
				wt.currency AS currency,
				'SUCCESS' AS status,
				NULL AS plan_id,
				NULL AS plan_name,
				wt.id AS invoice_id,
				? AS kind,
				NULL AS term_months,
				NULL AS payment_method,
				NULL AS expires_at,
				wt.created_at AS created_at
			FROM wallet_transactions AS wt
			WHERE wt.user_id = ? AND wt.type = ? AND wt.payment_id IS NULL
		)
	`

	var total int64
	if err := m.runtime.DB().WithContext(ctx).
		Raw(baseQuery+`SELECT COUNT(*) FROM history`, common.PaymentKindSubscription, queryValue.UserID, common.PaymentKindWalletTopup, queryValue.UserID, common.WalletTransactionTypeTopup).
		Scan(&total).Error; err != nil {
		return nil, err
	}

	var rows []paymentHistoryRow
	if err := m.runtime.DB().WithContext(ctx).
		Raw(baseQuery+`SELECT * FROM history ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, common.PaymentKindSubscription, queryValue.UserID, common.PaymentKindWalletTopup, queryValue.UserID, common.WalletTransactionTypeTopup, limit, offset).
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	items := make([]PaymentHistoryItem, 0, len(rows))
	for _, row := range rows {
		var expiresAt *string
		if row.ExpiresAt != nil {
			value := row.ExpiresAt.UTC().Format(time.RFC3339)
			expiresAt = &value
		}
		var createdAt *string
		if row.CreatedAt != nil {
			value := row.CreatedAt.UTC().Format(time.RFC3339)
			createdAt = &value
		}
		items = append(items, PaymentHistoryItem{
			ID:            row.ID,
			Amount:        row.Amount,
			Currency:      common.NormalizeCurrency(row.Currency),
			Status:        common.NormalizePaymentStatus(row.Status),
			PlanID:        row.PlanID,
			PlanName:      row.PlanName,
			InvoiceID:     common.BuildInvoiceID(row.InvoiceID),
			Kind:          row.Kind,
			TermMonths:    row.TermMonths,
			PaymentMethod: common.NormalizeOptionalPaymentMethod(row.PaymentMethod),
			ExpiresAt:     expiresAt,
			CreatedAt:     createdAt,
		})
	}

	hasPrev := page > 1 && total > 0
	hasNext := int64(offset)+int64(len(items)) < total
	return &PaymentHistoryResult{Items: items, Total: total, Page: page, Limit: limit, HasPrev: hasPrev, HasNext: hasNext}, nil
}

func (m *Module) TopupWallet(ctx context.Context, cmd TopupWalletCommand) (*TopupWalletResult, error) {
	if cmd.Amount < 1 {
		return nil, status.Error(codes.InvalidArgument, "Amount must be at least 1")
	}
	transaction := &model.WalletTransaction{
		ID:       uuid.New().String(),
		UserID:   cmd.UserID,
		Type:     common.WalletTransactionTypeTopup,
		Amount:   cmd.Amount,
		Currency: model.StringPtr("USD"),
		Note:     model.StringPtr(fmt.Sprintf("Wallet top-up of %.2f USD", cmd.Amount)),
	}
	notification := &model.Notification{
		ID:      uuid.New().String(),
		UserID:  cmd.UserID,
		Type:    "billing.topup",
		Title:   "Wallet credited",
		Message: fmt.Sprintf("Your wallet has been credited with %.2f USD.", cmd.Amount),
		Metadata: model.StringPtr(common.MustMarshalJSON(map[string]any{
			"wallet_transaction_id": transaction.ID,
			"invoice_id":            common.BuildInvoiceID(transaction.ID),
		})),
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := common.LockUserForUpdate(ctx, tx, cmd.UserID); err != nil {
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
		return nil, err
	}
	balance, err := model.GetWalletBalance(ctx, m.runtime.DB(), cmd.UserID)
	if err != nil {
		return nil, err
	}
	return &TopupWalletResult{WalletTransaction: transaction, WalletBalance: balance, InvoiceID: common.BuildInvoiceID(transaction.ID)}, nil
}

func (m *Module) DownloadInvoice(ctx context.Context, queryValue DownloadInvoiceQuery) (*DownloadInvoiceResult, error) {
	if queryValue.ID == "" {
		return nil, status.Error(codes.NotFound, "Invoice not found")
	}
	paymentRecord, err := query.Payment.WithContext(ctx).Where(query.Payment.ID.Eq(queryValue.ID), query.Payment.UserID.Eq(queryValue.UserID)).First()
	if err == nil {
		invoiceText, filename, buildErr := m.BuildPaymentInvoice(ctx, paymentRecord)
		if buildErr != nil {
			return nil, buildErr
		}
		return &DownloadInvoiceResult{Filename: filename, ContentType: "text/plain; charset=utf-8", Content: invoiceText}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	var topup model.WalletTransaction
	if err := m.runtime.DB().WithContext(ctx).
		Where("id = ? AND user_id = ? AND type = ? AND payment_id IS NULL", queryValue.ID, queryValue.UserID, common.WalletTransactionTypeTopup).
		First(&topup).Error; err == nil {
		return &DownloadInvoiceResult{Filename: common.BuildInvoiceFilename(topup.ID), ContentType: "text/plain; charset=utf-8", Content: common.BuildTopupInvoice(&topup)}, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return nil, status.Error(codes.NotFound, "Invoice not found")
}

func (m *Module) LoadPaymentPlanForUser(ctx context.Context, planID string) (*model.Plan, error) {
	var planRecord model.Plan
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		m.runtime.Logger().Error("Failed to load plan", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}
	return &planRecord, nil
}

func (m *Module) LoadPaymentPlanForAdmin(ctx context.Context, planID string) (*model.Plan, error) {
	var planRecord model.Plan
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}
	return &planRecord, nil
}

func (m *Module) LoadPaymentUserForAdmin(ctx context.Context, userID string) (*model.User, error) {
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	return &user, nil
}

func (m *Module) ExecutePaymentFlow(ctx context.Context, input ExecutionInput) (*ExecutionResult, error) {
	totalAmount := input.Plan.Price * float64(input.TermMonths)
	if totalAmount < 0 {
		return nil, status.Error(codes.InvalidArgument, "Amount must be greater than or equal to 0")
	}
	statusValue := "SUCCESS"
	provider := "INTERNAL"
	currency := common.NormalizeCurrency(nil)
	transactionID := common.BuildTransactionID("sub")
	now := time.Now().UTC()
	paymentRecord := &model.Payment{ID: uuid.New().String(), UserID: input.UserID, PlanID: &input.Plan.ID, Amount: totalAmount, Currency: &currency, Status: &statusValue, Provider: &provider, TransactionID: &transactionID}
	invoiceID := common.BuildInvoiceID(paymentRecord.ID)
	result := &ExecutionResult{Payment: paymentRecord, InvoiceID: invoiceID}
	err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := common.LockUserForUpdate(ctx, tx, input.UserID); err != nil {
			return err
		}
		newExpiry, err := loadPaymentExpiry(ctx, tx, input.UserID, input.TermMonths, now)
		if err != nil {
			return err
		}
		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		validatedTopupAmount, err := ValidatePaymentFunding(input, totalAmount, currentWalletBalance)
		if err != nil {
			return err
		}
		if err := tx.Create(paymentRecord).Error; err != nil {
			return err
		}
		if err := createPaymentWalletTransactions(tx, input, paymentRecord, totalAmount, validatedTopupAmount, currency); err != nil {
			return err
		}
		subscription := buildPaymentSubscription(input, paymentRecord, totalAmount, validatedTopupAmount, now, newExpiry)
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", input.UserID).Update("plan_id", input.Plan.ID).Error; err != nil {
			return err
		}
		if err := tx.Create(buildSubscriptionNotification(input.UserID, paymentRecord.ID, invoiceID, input.Plan, subscription)).Error; err != nil {
			return err
		}
		if _, err := m.MaybeGrantReferralReward(ctx, tx, input, paymentRecord, subscription); err != nil {
			return err
		}
		walletBalance, err := model.GetWalletBalance(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		result.Subscription = subscription
		result.WalletBalance = walletBalance
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func loadPaymentExpiry(ctx context.Context, tx *gorm.DB, userID string, termMonths int32, now time.Time) (time.Time, error) {
	currentSubscription, err := model.GetLatestPlanSubscription(ctx, tx, userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, err
	}
	baseExpiry := now
	if currentSubscription != nil && currentSubscription.ExpiresAt.After(baseExpiry) {
		baseExpiry = currentSubscription.ExpiresAt.UTC()
	}
	return baseExpiry.AddDate(0, int(termMonths), 0), nil
}

func ValidatePaymentFunding(input ExecutionInput, totalAmount, currentWalletBalance float64) (float64, error) {
	shortfall := common.MaxFloat(totalAmount-currentWalletBalance, 0)
	if input.PaymentMethod == common.PaymentMethodWallet && shortfall > 0 {
		return 0, newValidationError("Insufficient wallet balance", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if input.PaymentMethod != common.PaymentMethodTopup {
		return 0, nil
	}
	if input.TopupAmount == nil {
		return 0, newValidationError("Top-up amount is required when payment method is topup", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	topupAmount := common.MaxFloat(*input.TopupAmount, 0)
	if topupAmount <= 0 {
		return 0, newValidationError("Top-up amount must be greater than 0", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if topupAmount < shortfall {
		return 0, newValidationError("Top-up amount must be greater than or equal to the required shortfall", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
			"topup_amount":   topupAmount,
		})
	}
	return topupAmount, nil
}

func createPaymentWalletTransactions(tx *gorm.DB, input ExecutionInput, paymentRecord *model.Payment, totalAmount, topupAmount float64, currency string) error {
	if input.PaymentMethod == common.PaymentMethodTopup {
		topupTransaction := &model.WalletTransaction{ID: uuid.New().String(), UserID: input.UserID, Type: common.WalletTransactionTypeTopup, Amount: topupAmount, Currency: model.StringPtr(currency), Note: model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", input.Plan.Name, input.TermMonths)), PaymentID: &paymentRecord.ID, PlanID: &input.Plan.ID, TermMonths: common.Int32Ptr(input.TermMonths)}
		if err := tx.Create(topupTransaction).Error; err != nil {
			return err
		}
	}
	debitTransaction := &model.WalletTransaction{ID: uuid.New().String(), UserID: input.UserID, Type: common.WalletTransactionTypeSubscriptionDebit, Amount: -totalAmount, Currency: model.StringPtr(currency), Note: model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", input.Plan.Name, input.TermMonths)), PaymentID: &paymentRecord.ID, PlanID: &input.Plan.ID, TermMonths: common.Int32Ptr(input.TermMonths)}
	return tx.Create(debitTransaction).Error
}

func buildPaymentSubscription(input ExecutionInput, paymentRecord *model.Payment, totalAmount, topupAmount float64, now, newExpiry time.Time) *model.PlanSubscription {
	return &model.PlanSubscription{ID: uuid.New().String(), UserID: input.UserID, PaymentID: paymentRecord.ID, PlanID: input.Plan.ID, TermMonths: input.TermMonths, PaymentMethod: input.PaymentMethod, WalletAmount: totalAmount, TopupAmount: topupAmount, StartedAt: now, ExpiresAt: newExpiry}
}

func buildSubscriptionNotification(userID, paymentID, invoiceID string, planRecord *model.Plan, subscription *model.PlanSubscription) *model.Notification {
	return &model.Notification{ID: uuid.New().String(), UserID: userID, Type: "billing.subscription", Title: "Subscription activated", Message: fmt.Sprintf("Your subscription to %s is active until %s.", planRecord.Name, subscription.ExpiresAt.UTC().Format("2006-01-02")), Metadata: model.StringPtr(common.MustMarshalJSON(map[string]any{"payment_id": paymentID, "invoice_id": invoiceID, "plan_id": planRecord.ID, "term_months": subscription.TermMonths, "payment_method": subscription.PaymentMethod, "wallet_amount": subscription.WalletAmount, "topup_amount": subscription.TopupAmount, "plan_expires_at": subscription.ExpiresAt.UTC().Format(time.RFC3339)}))}
}

func buildReferralRewardNotification(userID string, rewardAmount float64, referee *model.User, paymentRecord *model.Payment) *model.Notification {
	refereeLabel := strings.TrimSpace(referee.Email)
	if username := strings.TrimSpace(common.StringValue(referee.Username)); username != "" {
		refereeLabel = "@" + username
	}
	return &model.Notification{ID: uuid.New().String(), UserID: userID, Type: "billing.referral_reward", Title: "Referral reward granted", Message: fmt.Sprintf("You received %.2f USD from %s's first subscription.", rewardAmount, refereeLabel), Metadata: model.StringPtr(common.MustMarshalJSON(map[string]any{"payment_id": paymentRecord.ID, "referee_id": referee.ID, "amount": rewardAmount}))}
}

func (m *Module) MaybeGrantReferralReward(ctx context.Context, tx *gorm.DB, input ExecutionInput, paymentRecord *model.Payment, subscription *model.PlanSubscription) (*ReferralRewardResult, error) {
	if paymentRecord == nil || subscription == nil || input.Plan == nil {
		return &ReferralRewardResult{}, nil
	}
	if subscription.PaymentMethod != common.PaymentMethodWallet && subscription.PaymentMethod != common.PaymentMethodTopup {
		return &ReferralRewardResult{}, nil
	}
	referee, err := common.LockUserForUpdate(ctx, tx, input.UserID)
	if err != nil {
		return nil, err
	}
	if referee.ReferredByUserID == nil || strings.TrimSpace(*referee.ReferredByUserID) == "" {
		return &ReferralRewardResult{}, nil
	}
	if common.ReferralRewardProcessed(referee) {
		return &ReferralRewardResult{}, nil
	}
	var subscriptionCount int64
	if err := tx.WithContext(ctx).Model(&model.PlanSubscription{}).Where("user_id = ?", referee.ID).Count(&subscriptionCount).Error; err != nil {
		return nil, err
	}
	if subscriptionCount != 1 {
		return &ReferralRewardResult{}, nil
	}
	referrer, err := common.LockUserForUpdate(ctx, tx, strings.TrimSpace(*referee.ReferredByUserID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &ReferralRewardResult{}, nil
		}
		return nil, err
	}
	if referrer.ID == referee.ID || !common.ReferralUserEligible(referrer) {
		return &ReferralRewardResult{}, nil
	}
	bps := common.EffectiveReferralRewardBps(referrer.ReferralRewardBps)
	if bps <= 0 {
		return &ReferralRewardResult{}, nil
	}
	baseAmount := input.Plan.Price * float64(input.TermMonths)
	if baseAmount <= 0 {
		return &ReferralRewardResult{}, nil
	}
	rewardAmount := baseAmount * float64(bps) / 10000
	if rewardAmount <= 0 {
		return &ReferralRewardResult{}, nil
	}
	currency := common.NormalizeCurrency(paymentRecord.Currency)
	rewardTransaction := &model.WalletTransaction{ID: uuid.New().String(), UserID: referrer.ID, Type: common.WalletTransactionTypeReferralReward, Amount: rewardAmount, Currency: model.StringPtr(currency), Note: model.StringPtr(fmt.Sprintf("Referral reward for %s first subscription", referee.Email)), PaymentID: &paymentRecord.ID, PlanID: &input.Plan.ID}
	if err := tx.Create(rewardTransaction).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(buildReferralRewardNotification(referrer.ID, rewardAmount, referee, paymentRecord)).Error; err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	updates := map[string]any{"referral_reward_granted_at": now, "referral_reward_payment_id": paymentRecord.ID, "referral_reward_amount": rewardAmount}
	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", referee.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	referee.ReferralRewardGrantedAt = &now
	referee.ReferralRewardPaymentID = &paymentRecord.ID
	referee.ReferralRewardAmount = &rewardAmount
	return &ReferralRewardResult{Granted: true, Amount: rewardAmount}, nil
}

func (m *Module) BuildPaymentInvoice(ctx context.Context, paymentRecord *model.Payment) (string, string, error) {
	details, err := m.LoadPaymentInvoiceDetails(ctx, paymentRecord)
	if err != nil {
		return "", "", err
	}
	createdAt := common.FormatOptionalTimestamp(paymentRecord.CreatedAt)
	lines := []string{"Stream API Invoice", fmt.Sprintf("Invoice ID: %s", common.BuildInvoiceID(paymentRecord.ID)), fmt.Sprintf("Payment ID: %s", paymentRecord.ID), fmt.Sprintf("User ID: %s", paymentRecord.UserID), fmt.Sprintf("Plan: %s", details.PlanName), fmt.Sprintf("Amount: %.2f %s", paymentRecord.Amount, common.NormalizeCurrency(paymentRecord.Currency)), fmt.Sprintf("Status: %s", strings.ToUpper(common.NormalizePaymentStatus(paymentRecord.Status))), fmt.Sprintf("Provider: %s", strings.ToUpper(common.StringValue(paymentRecord.Provider))), fmt.Sprintf("Payment Method: %s", strings.ToUpper(details.PaymentMethod)), fmt.Sprintf("Transaction ID: %s", common.StringValue(paymentRecord.TransactionID))}
	if details.TermMonths != nil { lines = append(lines, fmt.Sprintf("Term: %d month(s)", *details.TermMonths)) }
	if details.ExpiresAt != nil { lines = append(lines, fmt.Sprintf("Valid Until: %s", details.ExpiresAt.UTC().Format(time.RFC3339))) }
	if details.WalletAmount > 0 { lines = append(lines, fmt.Sprintf("Wallet Applied: %.2f %s", details.WalletAmount, common.NormalizeCurrency(paymentRecord.Currency))) }
	if details.TopupAmount > 0 { lines = append(lines, fmt.Sprintf("Top-up Added: %.2f %s", details.TopupAmount, common.NormalizeCurrency(paymentRecord.Currency))) }
	lines = append(lines, fmt.Sprintf("Created At: %s", createdAt))
	return strings.Join(lines, "\n"), common.BuildInvoiceFilename(paymentRecord.ID), nil
}

func (m *Module) LoadPaymentInvoiceDetails(ctx context.Context, paymentRecord *model.Payment) (*InvoiceDetails, error) {
	details := &InvoiceDetails{PlanName: "Unknown plan", PaymentMethod: common.PaymentMethodWallet}
	if paymentRecord.PlanID != nil && strings.TrimSpace(*paymentRecord.PlanID) != "" {
		var planRecord model.Plan
		if err := m.runtime.DB().WithContext(ctx).Where("id = ?", *paymentRecord.PlanID).First(&planRecord).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
		} else {
			details.PlanName = planRecord.Name
		}
	}
	var subscription model.PlanSubscription
	if err := m.runtime.DB().WithContext(ctx).Where("payment_id = ?", paymentRecord.ID).Order("created_at DESC").First(&subscription).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return details, nil
	}
	termMonths := subscription.TermMonths
	details.TermMonths = &termMonths
	details.PaymentMethod = common.NormalizePaymentMethod(subscription.PaymentMethod)
	if details.PaymentMethod == "" { details.PaymentMethod = common.PaymentMethodWallet }
	details.ExpiresAt = &subscription.ExpiresAt
	details.WalletAmount = subscription.WalletAmount
	details.TopupAmount = subscription.TopupAmount
	return details, nil
}

func (m *Module) ListAdminPayments(ctx context.Context, queryValue ListAdminPaymentsQuery) (*ListAdminPaymentsResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)
	limitInt := int(limit)
	db := m.runtime.DB().WithContext(ctx).Model(&model.Payment{})
	if queryValue.UserID != "" { db = db.Where("user_id = ?", queryValue.UserID) }
	if queryValue.StatusFilter != "" { db = db.Where("UPPER(status) = ?", strings.ToUpper(queryValue.StatusFilter)) }
	var total int64
	if err := db.Count(&total).Error; err != nil { return nil, err }
	var payments []model.Payment
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&payments).Error; err != nil { return nil, err }
	items := make([]AdminPaymentView, 0, len(payments))
	for _, payment := range payments {
		payload, err := m.BuildAdminPayment(ctx, &payment)
		if err != nil { return nil, err }
		items = append(items, payload)
	}
	return &ListAdminPaymentsResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetAdminPayment(ctx context.Context, queryValue GetAdminPaymentQuery) (*AdminPaymentView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if queryValue.ID == "" { return nil, status.Error(codes.NotFound, "Payment not found") }
	var payment model.Payment
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", queryValue.ID).First(&payment).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.NotFound, "Payment not found") }; return nil, status.Error(codes.Internal, "Failed to get payment") }
	payload, err := m.BuildAdminPayment(ctx, &payment)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to get payment") }
	return &payload, nil
}

func (m *Module) CreateAdminPayment(ctx context.Context, cmd CreateAdminPaymentCommand) (*CreateAdminPaymentResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	user, err := m.LoadPaymentUserForAdmin(ctx, cmd.UserID)
	if err != nil { return nil, err }
	planRecord, err := m.LoadPaymentPlanForAdmin(ctx, cmd.PlanID)
	if err != nil { return nil, err }
	resultValue, err := m.ExecutePaymentFlow(ctx, ExecutionInput{UserID: user.ID, Plan: planRecord, TermMonths: cmd.TermMonths, PaymentMethod: cmd.PaymentMethod, TopupAmount: cmd.TopupAmount})
	if err != nil { return nil, err }
	payload, err := m.BuildAdminPayment(ctx, resultValue.Payment)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to create payment") }
	return &CreateAdminPaymentResult{Payment: payload, Subscription: resultValue.Subscription, WalletBalance: resultValue.WalletBalance, InvoiceID: resultValue.InvoiceID}, nil
}

func (m *Module) UpdateAdminPayment(ctx context.Context, cmd UpdateAdminPaymentCommand) (*AdminPaymentView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil { return nil, err }
	if cmd.ID == "" { return nil, status.Error(codes.NotFound, "Payment not found") }
	newStatus := strings.ToUpper(strings.TrimSpace(cmd.NewStatus))
	if newStatus == "" { newStatus = "SUCCESS" }
	if newStatus != "SUCCESS" && newStatus != "FAILED" && newStatus != "PENDING" { return nil, status.Error(codes.InvalidArgument, "Invalid payment status") }
	var payment model.Payment
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).First(&payment).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.NotFound, "Payment not found") }; return nil, status.Error(codes.Internal, "Failed to update payment") }
	currentStatus := strings.ToUpper(common.NormalizePaymentStatus(payment.Status))
	if currentStatus != newStatus {
		if (currentStatus == "FAILED" || currentStatus == "PENDING") && newStatus == "SUCCESS" { return nil, status.Error(codes.InvalidArgument, "Cannot transition payment to SUCCESS from admin update; recreate through the payment flow instead") }
		payment.Status = model.StringPtr(newStatus)
		if err := m.runtime.DB().WithContext(ctx).Save(&payment).Error; err != nil { return nil, status.Error(codes.Internal, "Failed to update payment") }
	}
	payload, err := m.BuildAdminPayment(ctx, &payment)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to update payment") }
	return &payload, nil
}

func (m *Module) BuildAdminPayment(ctx context.Context, payment *model.Payment) (AdminPaymentView, error) {
	if payment == nil { return AdminPaymentView{}, nil }
	createdAt := payment.CreatedAt.UTC().Format(time.RFC3339)
	updatedAt := payment.UpdatedAt.UTC().Format(time.RFC3339)
	view := AdminPaymentView{ID: payment.ID, UserID: payment.UserID, PlanID: common.NullableTrimmedString(payment.PlanID), Amount: payment.Amount, Currency: common.NormalizeCurrency(payment.Currency), Status: common.NormalizePaymentStatus(payment.Status), Provider: strings.ToUpper(common.StringValue(payment.Provider)), TransactionID: common.NullableTrimmedString(payment.TransactionID), InvoiceID: payment.ID, CreatedAt: &createdAt, UpdatedAt: &updatedAt}
	userEmail, err := m.loadAdminUserEmail(ctx, payment.UserID)
	if err != nil { return AdminPaymentView{}, err }
	view.UserEmail = userEmail
	planName, err := m.loadAdminPlanName(ctx, payment.PlanID)
	if err != nil { return AdminPaymentView{}, err }
	view.PlanName = planName
	termMonths, paymentMethod, expiresAt, walletAmount, topupAmount, err := m.loadAdminPaymentSubscriptionDetails(ctx, payment.ID)
	if err != nil { return AdminPaymentView{}, err }
	view.TermMonths = termMonths
	view.PaymentMethod = paymentMethod
	view.ExpiresAt = expiresAt
	view.WalletAmount = walletAmount
	view.TopupAmount = topupAmount
	return view, nil
}

func (m *Module) loadAdminUserEmail(ctx context.Context, userID string) (*string, error) {
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Select("id, email").Where("id = ?", userID).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, nil }; return nil, err }
	return common.NullableTrimmedString(&user.Email), nil
}

func (m *Module) loadAdminPlanName(ctx context.Context, planID *string) (*string, error) {
	if planID == nil || strings.TrimSpace(*planID) == "" { return nil, nil }
	var plan model.Plan
	if err := m.runtime.DB().WithContext(ctx).Select("id, name").Where("id = ?", *planID).First(&plan).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, nil }; return nil, err }
	return common.NullableTrimmedString(&plan.Name), nil
}

func (m *Module) loadAdminPaymentSubscriptionDetails(ctx context.Context, paymentID string) (*int32, *string, *string, *float64, *float64, error) {
	var subscription model.PlanSubscription
	if err := m.runtime.DB().WithContext(ctx).Where("payment_id = ?", paymentID).Order("created_at DESC").First(&subscription).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, nil, nil, nil, nil, nil }; return nil, nil, nil, nil, nil, err }
	termMonths := subscription.TermMonths
	paymentMethod := common.NullableTrimmedString(&subscription.PaymentMethod)
	expiresAt := subscription.ExpiresAt.UTC().Format(time.RFC3339)
	walletAmount := subscription.WalletAmount
	topupAmount := subscription.TopupAmount
	return &termMonths, paymentMethod, common.NullableTrimmedString(&expiresAt), &walletAmount, &topupAmount, nil
}
