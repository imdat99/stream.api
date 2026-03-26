package service

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
)

var (
	errEmailRequired          = errors.New("Email is required")
	errEmailAlreadyRegistered = errors.New("Email already registered")
)

type updateProfileInput struct {
	Username *string
	Email    *string
	Language *string
	Locale   *string
}

func updateUserProfile(ctx context.Context, userRepo UserRepository, prefRepo UserPreferenceRepository, l logger.Logger, userID string, req updateProfileInput) (*model.User, error) {
	updates := map[string]any{}
	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		updates["username"] = username
	}
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			return nil, errEmailRequired
		}
		updates["email"] = email
	}

	if len(updates) > 0 {
		if err := userRepo.UpdateFieldsByID(ctx, userID, updates); err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return nil, errEmailAlreadyRegistered
			}
			l.Error("Failed to update user", "error", err)
			return nil, err
		}
	}

	pref, err := prefRepo.FindOrCreateByUserID(ctx, userID)
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
		if err := prefRepo.Save(ctx, pref); err != nil {
			l.Error("Failed to save user preference", "error", err)
			return nil, err
		}
	}

	return userRepo.GetByID(ctx, userID)
}
