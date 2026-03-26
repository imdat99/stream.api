package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
)

type playerConfigRepository struct {
	db *gorm.DB
}

func NewPlayerConfigRepository(db *gorm.DB) *playerConfigRepository {
	return &playerConfigRepository{db: db}
}

func (r *playerConfigRepository) ListByUser(ctx context.Context, userID string) ([]model.PlayerConfig, error) {
	var items []model.PlayerConfig
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Order("is_default DESC").
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (r *playerConfigRepository) ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.PlayerConfig, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.PlayerConfig{})
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

	var items []model.PlayerConfig
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *playerConfigRepository) CountByUser(ctx context.Context, userID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.PlayerConfig{}).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *playerConfigRepository) CountByUserTx(tx *gorm.DB, ctx context.Context, userID string) (int64, error) {
	var count int64
	if err := tx.WithContext(ctx).
		Model(&model.PlayerConfig{}).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *playerConfigRepository) Create(ctx context.Context, item *model.PlayerConfig) error {
	return r.db.WithContext(ctx).Create(item).Error
}

func (r *playerConfigRepository) CreateWithDefault(ctx context.Context, userID string, item *model.PlayerConfig) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := r.UnsetDefaultForUserTx(tx, userID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	})
}

func (r *playerConfigRepository) CreateTx(tx *gorm.DB, ctx context.Context, item *model.PlayerConfig) error {
	return tx.Create(item).Error
}

func (r *playerConfigRepository) GetByIDAndUser(ctx context.Context, id string, userID string) (*model.PlayerConfig, error) {
	var item model.PlayerConfig
	if err := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *playerConfigRepository) GetByID(ctx context.Context, id string) (*model.PlayerConfig, error) {
	var item model.PlayerConfig
	if err := r.db.WithContext(ctx).
		Where("id = ?", strings.TrimSpace(id)).
		First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *playerConfigRepository) GetByIDAndUserTx(tx *gorm.DB, ctx context.Context, id string, userID string) (*model.PlayerConfig, error) {
	var item model.PlayerConfig
	if err := tx.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *playerConfigRepository) Save(ctx context.Context, item *model.PlayerConfig) error {
	return r.db.WithContext(ctx).Save(item).Error
}

func (r *playerConfigRepository) SaveWithDefault(ctx context.Context, userID string, item *model.PlayerConfig) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := r.UnsetDefaultForUserTx(tx, userID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(item).Error
	})
}

func (r *playerConfigRepository) SaveTx(tx *gorm.DB, ctx context.Context, item *model.PlayerConfig) error {
	return tx.Save(item).Error
}

func (r *playerConfigRepository) DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Delete(&model.PlayerConfig{})
	return res.RowsAffected, res.Error
}

func (r *playerConfigRepository) DeleteByID(ctx context.Context, id string) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("id = ?", strings.TrimSpace(id)).
		Delete(&model.PlayerConfig{})
	return res.RowsAffected, res.Error
}

func (r *playerConfigRepository) DeleteByIDAndUserTx(tx *gorm.DB, ctx context.Context, id string, userID string) (int64, error) {
	res := tx.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(id), strings.TrimSpace(userID)).
		Delete(&model.PlayerConfig{})
	return res.RowsAffected, res.Error
}

func (r *playerConfigRepository) UnsetDefaultForUser(ctx context.Context, userID string, excludeID string) error {
	updates := map[string]any{"is_default": false}
	db := r.db.WithContext(ctx).Model(&model.PlayerConfig{}).Where("user_id = ?", strings.TrimSpace(userID))
	if strings.TrimSpace(excludeID) != "" {
		db = db.Where("id != ?", strings.TrimSpace(excludeID))
	}
	return db.Updates(updates).Error
}

func (r *playerConfigRepository) UnsetDefaultForUserTx(tx *gorm.DB, userID string, excludeID string) error {
	updates := map[string]any{"is_default": false}
	db := tx.Model(&model.PlayerConfig{}).Where("user_id = ?", strings.TrimSpace(userID))
	if strings.TrimSpace(excludeID) != "" {
		db = db.Where("id != ?", strings.TrimSpace(excludeID))
	}
	return db.Updates(updates).Error
}

func (r *playerConfigRepository) CreateManaged(ctx context.Context, userID string, item *model.PlayerConfig, validate func(*model.User, int64) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := r.lockUserForUpdateTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		configCount, err := r.CountByUserTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		if err := validate(lockedUser, configCount); err != nil {
			return err
		}
		if item.IsDefault {
			if err := r.UnsetDefaultForUserTx(tx, userID, ""); err != nil {
				return err
			}
		}
		return r.CreateTx(tx, ctx, item)
	})
}

func (r *playerConfigRepository) UpdateManaged(ctx context.Context, userID string, id string, mutateAndValidate func(*model.PlayerConfig, *model.User, int64) error) (*model.PlayerConfig, error) {
	var item *model.PlayerConfig
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := r.lockUserForUpdateTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		configCount, err := r.CountByUserTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		item, err = r.GetByIDAndUserTx(tx, ctx, id, userID)
		if err != nil {
			return err
		}
		if err := mutateAndValidate(item, lockedUser, configCount); err != nil {
			return err
		}
		if item.IsDefault {
			if err := r.UnsetDefaultForUserTx(tx, userID, item.ID); err != nil {
				return err
			}
		}
		return r.SaveTx(tx, ctx, item)
	})
	return item, err
}

func (r *playerConfigRepository) DeleteManaged(ctx context.Context, userID string, id string, validate func(*model.User, int64) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := r.lockUserForUpdateTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		configCount, err := r.CountByUserTx(tx, ctx, userID)
		if err != nil {
			return err
		}
		if err := validate(lockedUser, configCount); err != nil {
			return err
		}
		rowsAffected, err := r.DeleteByIDAndUserTx(tx, ctx, id, userID)
		if err != nil {
			return err
		}
		if rowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}

func (r *playerConfigRepository) lockUserForUpdateTx(tx *gorm.DB, ctx context.Context, userID string) (*model.User, error) {
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
