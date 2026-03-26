package service

import (
	"context"
	"strings"

	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
)

type updatePreferencesInput struct {
	EmailNotifications     *bool
	PushNotifications      *bool
	MarketingNotifications *bool
	TelegramNotifications  *bool
	Language               *string
	Locale                 *string
}

func loadUserPreferences(ctx context.Context, prefRepo UserPreferenceRepository, userID string) (*model.UserPreference, error) {
	return prefRepo.FindOrCreateByUserID(ctx, userID)
}

func updateUserPreferences(ctx context.Context, prefRepo UserPreferenceRepository, l logger.Logger, userID string, req updatePreferencesInput) (*model.UserPreference, error) {
	pref, err := prefRepo.FindOrCreateByUserID(ctx, userID)
	if err != nil {
		l.Error("Failed to load preferences", "error", err)
		return nil, err
	}

	if req.EmailNotifications != nil {
		pref.EmailNotifications = model.BoolPtr(*req.EmailNotifications)
	}
	if req.PushNotifications != nil {
		pref.PushNotifications = model.BoolPtr(*req.PushNotifications)
	}
	if req.MarketingNotifications != nil {
		pref.MarketingNotifications = *req.MarketingNotifications
	}
	if req.TelegramNotifications != nil {
		pref.TelegramNotifications = *req.TelegramNotifications
	}
	if req.Language != nil {
		pref.Language = model.StringPtr(strings.TrimSpace(*req.Language))
	}
	if req.Locale != nil {
		pref.Locale = model.StringPtr(strings.TrimSpace(*req.Locale))
	}
	if strings.TrimSpace(model.StringValue(pref.Language)) == "" {
		pref.Language = model.StringPtr("en")
	}
	if strings.TrimSpace(model.StringValue(pref.Locale)) == "" {
		pref.Locale = model.StringPtr(model.StringValue(pref.Language))
	}

	if err := prefRepo.Save(ctx, pref); err != nil {
		l.Error("Failed to save preferences", "error", err)
		return nil, err
	}

	return pref, nil
}
