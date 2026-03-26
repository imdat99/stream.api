package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
)

type PaymentHistoryRow struct {
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

type paymentRepository struct {
	db *gorm.DB
}

func NewPaymentRepository(db *gorm.DB) *paymentRepository {
	return &paymentRepository{db: db}
}

func (r *paymentRepository) ListHistoryByUser(ctx context.Context, userID string, subscriptionKind string, walletTopupKind string, topupType string, limit int32, offset int) ([]PaymentHistoryRow, int64, error) {
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
	if err := r.db.WithContext(ctx).
		Raw(baseQuery+`SELECT COUNT(*) FROM history`, subscriptionKind, userID, walletTopupKind, userID, topupType).
		Scan(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []PaymentHistoryRow
	if err := r.db.WithContext(ctx).
		Raw(baseQuery+`SELECT * FROM history ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, subscriptionKind, userID, walletTopupKind, userID, topupType, limit, offset).
		Scan(&rows).Error; err != nil {
		return nil, 0, err
	}

	return rows, total, nil
}

func (r *paymentRepository) ListForAdmin(ctx context.Context, userID string, status string, limit int32, offset int) ([]model.Payment, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.Payment{})
	if trimmedUserID := strings.TrimSpace(userID); trimmedUserID != "" {
		db = db.Where("user_id = ?", trimmedUserID)
	}
	if trimmedStatus := strings.TrimSpace(status); trimmedStatus != "" {
		db = db.Where("UPPER(status) = ?", strings.ToUpper(trimmedStatus))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var payments []model.Payment
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&payments).Error; err != nil {
		return nil, 0, err
	}
	return payments, total, nil
}

func (r *paymentRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.Payment{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *paymentRepository) SumSuccessfulAmount(ctx context.Context) (float64, error) {
	var total float64
	if err := r.db.WithContext(ctx).Model(&model.Payment{}).Where("status = ?", "SUCCESS").Select("COALESCE(SUM(amount), 0)").Scan(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func (r *paymentRepository) GetByID(ctx context.Context, paymentID string) (*model.Payment, error) {
	return query.Payment.WithContext(ctx).
		Where(query.Payment.ID.Eq(strings.TrimSpace(paymentID))).
		First()
}

func (r *paymentRepository) GetByIDAndUser(ctx context.Context, paymentID string, userID string) (*model.Payment, error) {
	return query.Payment.WithContext(ctx).
		Where(query.Payment.ID.Eq(strings.TrimSpace(paymentID)), query.Payment.UserID.Eq(strings.TrimSpace(userID))).
		First()
}

func (r *paymentRepository) GetStandaloneTopupByIDAndUser(ctx context.Context, id string, userID string, topupType string) (*model.WalletTransaction, error) {
	var topup model.WalletTransaction
	if err := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ? AND type = ? AND payment_id IS NULL", strings.TrimSpace(id), strings.TrimSpace(userID), topupType).
		First(&topup).Error; err != nil {
		return nil, err
	}
	return &topup, nil
}

func (r *paymentRepository) GetSubscriptionByPaymentID(ctx context.Context, paymentID string) (*model.PlanSubscription, error) {
	var subscription model.PlanSubscription
	if err := r.db.WithContext(ctx).
		Where("payment_id = ?", strings.TrimSpace(paymentID)).
		Order("created_at DESC").
		First(&subscription).Error; err != nil {
		return nil, err
	}
	return &subscription, nil
}

func (r *paymentRepository) CountByPlanID(ctx context.Context, planID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", strings.TrimSpace(planID)).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *paymentRepository) CreatePayment(ctx context.Context, payment *model.Payment) error {
	return r.db.WithContext(ctx).Create(payment).Error
}

func (r *paymentRepository) Save(ctx context.Context, payment *model.Payment) error {
	return r.db.WithContext(ctx).Save(payment).Error
}

func (r *paymentRepository) CreatePaymentTx(tx *gorm.DB, ctx context.Context, payment *model.Payment) error {
	return tx.Create(payment).Error
}

func (r *paymentRepository) CreateWalletTransactionTx(tx *gorm.DB, ctx context.Context, txRecord *model.WalletTransaction) error {
	return tx.Create(txRecord).Error
}

func (r *paymentRepository) CreatePlanSubscriptionTx(tx *gorm.DB, ctx context.Context, subscription *model.PlanSubscription) error {
	return tx.Create(subscription).Error
}

func (r *paymentRepository) UpdateUserPlanID(ctx context.Context, userID string, planID string) error {
	return r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).Update("plan_id", planID).Error
}

func (r *paymentRepository) UpdateUserPlanIDTx(tx *gorm.DB, ctx context.Context, userID string, planID string) error {
	return tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", strings.TrimSpace(userID)).Update("plan_id", strings.TrimSpace(planID)).Error
}

func (r *paymentRepository) CreateNotificationTx(tx *gorm.DB, ctx context.Context, notification *model.Notification) error {
	return tx.Create(notification).Error
}

func (r *paymentRepository) CreateWalletTopupAndNotification(ctx context.Context, userID string, transaction *model.WalletTransaction, notification *model.Notification) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := r.lockUserForUpdateTx(tx, ctx, userID); err != nil {
			return err
		}
		if err := r.CreateWalletTransactionTx(tx, ctx, transaction); err != nil {
			return err
		}
		return r.CreateNotificationTx(tx, ctx, notification)
	})
}

func (r *paymentRepository) ExecuteSubscriptionPayment(ctx context.Context, userID string, plan *model.Plan, termMonths int32, paymentMethod string, paymentRecord *model.Payment, invoiceID string, now time.Time, validateFunding func(currentWalletBalance float64) (float64, error)) (*model.PlanSubscription, float64, error) {
	var (
		subscription  *model.PlanSubscription
		walletBalance float64
	)

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		referee, err := r.lockUserForUpdateTx(tx, ctx, userID)
		if err != nil {
			return err
		}

		newExpiry, err := r.loadPaymentExpiryTx(tx, ctx, userID, termMonths, now)
		if err != nil {
			return err
		}
		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, userID)
		if err != nil {
			return err
		}
		validatedTopupAmount, err := validateFunding(currentWalletBalance)
		if err != nil {
			return err
		}
		if err := r.CreatePaymentTx(tx, ctx, paymentRecord); err != nil {
			return err
		}
		if err := r.createPaymentWalletTransactionsTx(tx, ctx, userID, plan, termMonths, paymentMethod, paymentRecord, paymentRecord.Amount, validatedTopupAmount, model.StringValue(paymentRecord.Currency)); err != nil {
			return err
		}

		subscription = &model.PlanSubscription{
			ID:            uuid.New().String(),
			UserID:        userID,
			PaymentID:     paymentRecord.ID,
			PlanID:        plan.ID,
			TermMonths:    termMonths,
			PaymentMethod: paymentMethod,
			WalletAmount:  paymentRecord.Amount,
			TopupAmount:   validatedTopupAmount,
			StartedAt:     now,
			ExpiresAt:     newExpiry,
		}
		if err := r.CreatePlanSubscriptionTx(tx, ctx, subscription); err != nil {
			return err
		}
		if err := r.UpdateUserPlanIDTx(tx, ctx, userID, plan.ID); err != nil {
			return err
		}

		notification := &model.Notification{
			ID:      uuid.New().String(),
			UserID:  userID,
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
		if err := r.CreateNotificationTx(tx, ctx, notification); err != nil {
			return err
		}
		if err := r.maybeGrantReferralRewardTx(tx, ctx, referee, plan, paymentRecord, subscription); err != nil {
			return err
		}
		walletBalance, err = model.GetWalletBalance(ctx, tx, userID)
		return err
	})

	return subscription, walletBalance, err
}

func (r *paymentRepository) lockUserForUpdateTx(tx *gorm.DB, ctx context.Context, userID string) (*model.User, error) {
	trimmedUserID := strings.TrimSpace(userID)
	if tx.Dialector.Name() == "sqlite" {
		res := tx.WithContext(ctx).Exec("UPDATE user SET id = id WHERE id = ?", trimmedUserID)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, gorm.ErrRecordNotFound
		}
	}

	var user model.User
	if err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", trimmedUserID).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *paymentRepository) loadPaymentExpiryTx(tx *gorm.DB, ctx context.Context, userID string, termMonths int32, now time.Time) (time.Time, error) {
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

func (r *paymentRepository) createPaymentWalletTransactionsTx(tx *gorm.DB, ctx context.Context, userID string, plan *model.Plan, termMonths int32, paymentMethod string, paymentRecord *model.Payment, totalAmount, topupAmount float64, currency string) error {
	if paymentMethod == "topup" {
		topupTransaction := &model.WalletTransaction{
			ID:         uuid.New().String(),
			UserID:     userID,
			Type:       "topup",
			Amount:     topupAmount,
			Currency:   model.StringPtr(currency),
			Note:       model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", plan.Name, termMonths)),
			PaymentID:  &paymentRecord.ID,
			PlanID:     &plan.ID,
			TermMonths: &termMonths,
		}
		if err := r.CreateWalletTransactionTx(tx, ctx, topupTransaction); err != nil {
			return err
		}
	}

	debitTransaction := &model.WalletTransaction{
		ID:         uuid.New().String(),
		UserID:     userID,
		Type:       "subscription_debit",
		Amount:     -totalAmount,
		Currency:   model.StringPtr(currency),
		Note:       model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", plan.Name, termMonths)),
		PaymentID:  &paymentRecord.ID,
		PlanID:     &plan.ID,
		TermMonths: &termMonths,
	}
	return r.CreateWalletTransactionTx(tx, ctx, debitTransaction)
}

func (r *paymentRepository) maybeGrantReferralRewardTx(tx *gorm.DB, ctx context.Context, referee *model.User, plan *model.Plan, paymentRecord *model.Payment, subscription *model.PlanSubscription) error {
	if paymentRecord == nil || subscription == nil || plan == nil || referee == nil {
		return nil
	}
	if subscription.PaymentMethod != "wallet" && subscription.PaymentMethod != "topup" {
		return nil
	}
	if referee.ReferredByUserID == nil || strings.TrimSpace(*referee.ReferredByUserID) == "" {
		return nil
	}
	if referee.ReferralRewardGrantedAt != nil || (referee.ReferralRewardPaymentID != nil && strings.TrimSpace(*referee.ReferralRewardPaymentID) != "") {
		return nil
	}

	var subscriptionCount int64
	if err := tx.WithContext(ctx).Model(&model.PlanSubscription{}).Where("user_id = ?", referee.ID).Count(&subscriptionCount).Error; err != nil {
		return err
	}
	if subscriptionCount != 1 {
		return nil
	}

	referrer, err := r.lockUserForUpdateTx(tx, ctx, strings.TrimSpace(*referee.ReferredByUserID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if referrer.ID == referee.ID || (referrer.ReferralEligible != nil && !*referrer.ReferralEligible) {
		return nil
	}

	bps := int32(500)
	if referrer.ReferralRewardBps != nil {
		bps = *referrer.ReferralRewardBps
		if bps < 0 {
			bps = 0
		}
		if bps > 10000 {
			bps = 10000
		}
	}
	if bps <= 0 {
		return nil
	}

	baseAmount := plan.Price * float64(subscription.TermMonths)
	if baseAmount <= 0 {
		return nil
	}
	rewardAmount := baseAmount * float64(bps) / 10000
	if rewardAmount <= 0 {
		return nil
	}

	refereeLabel := strings.TrimSpace(referee.Email)
	if username := strings.TrimSpace(model.StringValue(referee.Username)); username != "" {
		refereeLabel = "@" + username
	}

	rewardTransaction := &model.WalletTransaction{
		ID:        uuid.New().String(),
		UserID:    referrer.ID,
		Type:      "referral_reward",
		Amount:    rewardAmount,
		Currency:  paymentRecord.Currency,
		Note:      model.StringPtr(fmt.Sprintf("Referral reward for %s first subscription", referee.Email)),
		PaymentID: &paymentRecord.ID,
		PlanID:    &plan.ID,
	}
	if err := tx.Create(rewardTransaction).Error; err != nil {
		return err
	}
	notification := &model.Notification{
		ID:      uuid.New().String(),
		UserID:  referrer.ID,
		Type:    "billing.referral_reward",
		Title:   "Referral reward granted",
		Message: fmt.Sprintf("You received %.2f USD from %s's first subscription.", rewardAmount, refereeLabel),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
			"payment_id": paymentRecord.ID,
			"referee_id": referee.ID,
			"amount":     rewardAmount,
		})),
	}
	if err := tx.Create(notification).Error; err != nil {
		return err
	}

	now := time.Now().UTC()
	return tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", referee.ID).Updates(map[string]any{
		"referral_reward_granted_at": now,
		"referral_reward_payment_id": paymentRecord.ID,
		"referral_reward_amount":     rewardAmount,
	}).Error
}

func mustMarshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
