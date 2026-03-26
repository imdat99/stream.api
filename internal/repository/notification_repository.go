package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type notificationRepository struct {
	db *gorm.DB
}

func NewNotificationRepository(db *gorm.DB) *notificationRepository {
	return &notificationRepository{db: db}
}

func (r *notificationRepository) ListByUser(ctx context.Context, userID string) ([]model.Notification, error) {
	var rows []model.Notification
	err := r.db.WithContext(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *notificationRepository) MarkReadByIDAndUser(ctx context.Context, id string, userID string) (int64, error) {
	res := r.db.WithContext(ctx).
		Model(&model.Notification{}).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Update("is_read", true)
	return res.RowsAffected, res.Error
}

func (r *notificationRepository) MarkAllReadByUser(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).
		Model(&model.Notification{}).
		Where("user_id = ? AND is_read = ?", strings.TrimSpace(userID), false).
		Update("is_read", true).Error
}

func (r *notificationRepository) DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Delete(&model.Notification{})
	return res.RowsAffected, res.Error
}

func (r *notificationRepository) DeleteAllByUser(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Delete(&model.Notification{}).Error
}
