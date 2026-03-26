package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type adTemplateRepository struct {
	db *gorm.DB
}

func NewAdTemplateRepository(db *gorm.DB) *adTemplateRepository {
	return &adTemplateRepository{db: db}
}

func (r *adTemplateRepository) ListByUser(ctx context.Context, userID string) ([]model.AdTemplate, error) {
	var items []model.AdTemplate
	err := r.db.WithContext(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Order("is_default DESC").
		Order("created_at DESC").
		Find(&items).Error
	return items, err
}

func (r *adTemplateRepository) ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.AdTemplate, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.AdTemplate{})
	if trimmedSearch := strings.TrimSpace(search); trimmedSearch != "" {
		like := "%" + trimmedSearch + "%"
		db = db.Where("name ILIKE ?", like)
	}
	if trimmedUserID := strings.TrimSpace(userID); trimmedUserID != "" {
		db = db.Where("user_id = ?", trimmedUserID)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var templates []model.AdTemplate
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&templates).Error; err != nil {
		return nil, 0, err
	}
	return templates, total, nil
}

func (r *adTemplateRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.AdTemplate{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *adTemplateRepository) GetByID(ctx context.Context, id string) (*model.AdTemplate, error) {
	var item model.AdTemplate
	if err := r.db.WithContext(ctx).
		Where("id = ?", strings.TrimSpace(id)).
		First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *adTemplateRepository) GetByIDAndUser(ctx context.Context, id string, userID string) (*model.AdTemplate, error) {
	var item model.AdTemplate
	if err := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *adTemplateRepository) ExistsByIDAndUser(ctx context.Context, id string, userID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.AdTemplate{}).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Count(&count).Error
	return count > 0, err
}

func (r *adTemplateRepository) CreateWithDefault(ctx context.Context, userID string, item *model.AdTemplate) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := tx.Model(&model.AdTemplate{}).
				Where("user_id = ?", strings.TrimSpace(userID)).
				Update("is_default", false).Error; err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	})
}

func (r *adTemplateRepository) SaveWithDefault(ctx context.Context, userID string, item *model.AdTemplate) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := tx.Model(&model.AdTemplate{}).
				Where("user_id = ? AND id <> ?", strings.TrimSpace(userID), item.ID).
				Update("is_default", false).Error; err != nil {
				return err
			}
		}
		return tx.Save(item).Error
	})
}

func (r *adTemplateRepository) DeleteByIDAndUserAndClearVideos(ctx context.Context, id string, userID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Video{}).
			Where("user_id = ? AND ad_id = ?", strings.TrimSpace(userID), strings.TrimSpace(id)).
			Update("ad_id", nil).Error; err != nil {
			return err
		}

		res := tx.Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
			Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}

func (r *adTemplateRepository) DeleteByIDAndClearVideos(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Video{}).
			Where("ad_id = ?", strings.TrimSpace(id)).
			Update("ad_id", nil).Error; err != nil {
			return err
		}

		res := tx.Where("id = ?", strings.TrimSpace(id)).
			Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}
