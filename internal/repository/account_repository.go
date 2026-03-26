package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type accountRepository struct {
	db *gorm.DB
}

func NewAccountRepository(db *gorm.DB) *accountRepository {
	return &accountRepository{db: db}
}

func (r *accountRepository) DeleteUserAccount(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.WalletTransaction{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.PlanSubscription{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.UserPreference{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Payment{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", userID).Delete(&model.User{}).Error; err != nil {
			return err
		}
		return nil
	})
}

func (r *accountRepository) ClearUserData(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{"storage_used": 0}).Error; err != nil {
			return err
		}
		return nil
	})
}
