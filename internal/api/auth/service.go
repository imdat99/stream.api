package auth

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
)

var (
	ErrEmailRequired         = errors.New("Email is required")
	ErrEmailAlreadyRegistered = errors.New("Email already registered")
)

type UpdateProfileInput struct {
	Username *string
	Email    *string
	Language *string
	Locale   *string
}

func UpdateUserProfile(ctx context.Context, db *gorm.DB, l logger.Logger, userID string, req UpdateProfileInput) (*model.User, error) {
	updates := map[string]any{}
	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		updates["username"] = username
	}
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			return nil, ErrEmailRequired
		}
		updates["email"] = email
	}

	if len(updates) > 0 {
		if err := db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return nil, ErrEmailAlreadyRegistered
			}
			l.Error("Failed to update user", "error", err)
			return nil, err
		}
	}

	pref, err := model.FindOrCreateUserPreference(ctx, db, userID)
	if err != nil {
		l.Error("Failed to load user preference", "error", err)
		return nil, err
	}

	prefChanged := false
	if req.Language != nil {
		pref.Language = model.StringPtr(strings.TrimSpace(*req.Language))
		prefChanged = true
	}
	if req.Locale != nil {
		pref.Locale = model.StringPtr(strings.TrimSpace(*req.Locale))
		prefChanged = true
	}
	if strings.TrimSpace(model.StringValue(pref.Language)) == "" {
		pref.Language = model.StringPtr("en")
		prefChanged = true
	}
	if strings.TrimSpace(model.StringValue(pref.Locale)) == "" {
		pref.Locale = model.StringPtr(model.StringValue(pref.Language))
		prefChanged = true
	}
	if prefChanged {
		if err := db.WithContext(ctx).Save(pref).Error; err != nil {
			l.Error("Failed to save user preference", "error", err)
			return nil, err
		}
	}

	u := query.User
	user, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
	if err != nil {
		return nil, err
	}

	return user, nil
}
