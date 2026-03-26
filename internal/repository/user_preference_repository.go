package repository

import (
	"context"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type userPreferenceRepository struct {
	db *gorm.DB
}

func NewUserPreferenceRepository(db *gorm.DB) *userPreferenceRepository {
	return &userPreferenceRepository{db: db}
}

func (r *userPreferenceRepository) FindOrCreateByUserID(ctx context.Context, userID string) (*model.UserPreference, error) {
	return model.FindOrCreateUserPreference(ctx, r.db, userID)
}

func (r *userPreferenceRepository) Save(ctx context.Context, pref *model.UserPreference) error {
	return r.db.WithContext(ctx).Save(pref).Error
}
