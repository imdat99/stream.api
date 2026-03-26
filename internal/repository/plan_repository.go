package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type planRepository struct {
	db *gorm.DB
}

func NewPlanRepository(db *gorm.DB) *planRepository {
	return &planRepository{db: db}
}

func (r *planRepository) GetByID(ctx context.Context, planID string) (*model.Plan, error) {
	var plan model.Plan
	if err := r.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(planID)).First(&plan).Error; err != nil {
		return nil, err
	}
	return &plan, nil
}

func (r *planRepository) ListActive(ctx context.Context) ([]model.Plan, error) {
	var plans []model.Plan
	if err := r.db.WithContext(ctx).Where("is_active = ?", true).Find(&plans).Error; err != nil {
		return nil, err
	}
	return plans, nil
}

func (r *planRepository) ListAll(ctx context.Context) ([]model.Plan, error) {
	var plans []model.Plan
	if err := r.db.WithContext(ctx).Order("price ASC").Find(&plans).Error; err != nil {
		return nil, err
	}
	return plans, nil
}

func (r *planRepository) Create(ctx context.Context, plan *model.Plan) error {
	return r.db.WithContext(ctx).Create(plan).Error
}

func (r *planRepository) Save(ctx context.Context, plan *model.Plan) error {
	return r.db.WithContext(ctx).Save(plan).Error
}

func (r *planRepository) CountPaymentsByPlan(ctx context.Context, planID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", strings.TrimSpace(planID)).Count(&count).Error
	return count, err
}

func (r *planRepository) CountSubscriptionsByPlan(ctx context.Context, planID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", strings.TrimSpace(planID)).Count(&count).Error
	return count, err
}

func (r *planRepository) SetActive(ctx context.Context, planID string, isActive bool) error {
	return r.db.WithContext(ctx).Model(&model.Plan{}).Where("id = ?", strings.TrimSpace(planID)).Update("is_active", isActive).Error
}

func (r *planRepository) DeleteByID(ctx context.Context, planID string) error {
	return r.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(planID)).Delete(&model.Plan{}).Error
}
