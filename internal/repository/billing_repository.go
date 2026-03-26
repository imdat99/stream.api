package repository

import (
	"context"
	"time"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type billingRepository struct {
	db *gorm.DB
}

func NewBillingRepository(db *gorm.DB) *billingRepository {
	return &billingRepository{db: db}
}

func (r *billingRepository) GetWalletBalance(ctx context.Context, userID string) (float64, error) {
	return model.GetWalletBalance(ctx, r.db, userID)
}

func (r *billingRepository) GetWalletBalanceTx(tx *gorm.DB, ctx context.Context, userID string) (float64, error) {
	return model.GetWalletBalance(ctx, tx, userID)
}

func (r *billingRepository) GetLatestPlanSubscription(ctx context.Context, userID string) (*model.PlanSubscription, error) {
	return model.GetLatestPlanSubscription(ctx, r.db, userID)
}

func (r *billingRepository) GetLatestPlanSubscriptionTx(tx *gorm.DB, ctx context.Context, userID string) (*model.PlanSubscription, error) {
	return model.GetLatestPlanSubscription(ctx, tx, userID)
}

func (r *billingRepository) CountActiveSubscriptions(ctx context.Context, now time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.PlanSubscription{}).Where("expires_at > ?", now).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}
