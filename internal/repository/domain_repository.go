package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type domainRepository struct {
	db *gorm.DB
}

func NewDomainRepository(db *gorm.DB) *domainRepository {
	return &domainRepository{db: db}
}

func (r *domainRepository) ListByUser(ctx context.Context, userID string) ([]model.Domain, error) {
	var rows []model.Domain
	err := r.db.WithContext(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *domainRepository) CountByUserAndName(ctx context.Context, userID string, name string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.Domain{}).
		Where("user_id = ? AND name = ?", strings.TrimSpace(userID), strings.TrimSpace(name)).
		Count(&count).Error
	return count, err
}

func (r *domainRepository) Create(ctx context.Context, item *model.Domain) error {
	return r.db.WithContext(ctx).Create(item).Error
}

func (r *domainRepository) DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Delete(&model.Domain{})
	return res.RowsAffected, res.Error
}
