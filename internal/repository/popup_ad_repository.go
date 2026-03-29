package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type popupAdRepository struct {
	db *gorm.DB
}

func NewPopupAdRepository(db *gorm.DB) *popupAdRepository {
	return &popupAdRepository{db: db}
}

func (r *popupAdRepository) ListByUser(ctx context.Context, userID string, limit int32, offset int) ([]model.PopupAd, int64, error) {
	db := r.baseQuery(ctx).Model(&model.PopupAd{}).Where("user_id = ?", strings.TrimSpace(userID))

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []model.PopupAd
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *popupAdRepository) ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.PopupAd, int64, error) {
	db := r.baseQuery(ctx).Model(&model.PopupAd{})
	if trimmedSearch := strings.TrimSpace(search); trimmedSearch != "" {
		like := "%" + trimmedSearch + "%"
		db = db.Where("label ILIKE ?", like)
	}
	if trimmedUserID := strings.TrimSpace(userID); trimmedUserID != "" {
		db = db.Where("user_id = ?", trimmedUserID)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []model.PopupAd
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *popupAdRepository) GetByID(ctx context.Context, id string) (*model.PopupAd, error) {
	var item model.PopupAd
	if err := r.baseQuery(ctx).Where("id = ?", strings.TrimSpace(id)).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *popupAdRepository) GetByIDAndUser(ctx context.Context, id string, userID string) (*model.PopupAd, error) {
	var item model.PopupAd
	if err := r.baseQuery(ctx).Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *popupAdRepository) GetActiveByUser(ctx context.Context, userID string) (*model.PopupAd, error) {
	var item model.PopupAd
	err := r.baseQuery(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Where("is_active = ?", true).
		Order("created_at DESC").
		First(&item).Error
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *popupAdRepository) Create(ctx context.Context, item *model.PopupAd) error {
	return r.baseQuery(ctx).Create(item).Error
}

func (r *popupAdRepository) Save(ctx context.Context, item *model.PopupAd) error {
	return r.baseQuery(ctx).Save(item).Error
}

func (r *popupAdRepository) DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error) {
	res := r.baseQuery(ctx).Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).Delete(&model.PopupAd{})
	return res.RowsAffected, res.Error
}

func (r *popupAdRepository) DeleteByID(ctx context.Context, id string) (int64, error) {
	res := r.baseQuery(ctx).Where("id = ?", strings.TrimSpace(id)).Delete(&model.PopupAd{})
	return res.RowsAffected, res.Error
}

func (r *popupAdRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}
