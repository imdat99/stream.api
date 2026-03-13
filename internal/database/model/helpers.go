package model

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	defaultPreferenceLanguage = "en"
	defaultPreferenceLocale   = "en"
)

func DefaultUserPreference(userID string) *UserPreference {
	return &UserPreference{
		UserID:                 userID,
		Language:               StringPtr(defaultPreferenceLanguage),
		Locale:                 StringPtr(defaultPreferenceLocale),
		EmailNotifications:     BoolPtr(true),
		PushNotifications:      BoolPtr(true),
		MarketingNotifications: false,
		TelegramNotifications:  false,
		Autoplay:               false,
		Loop:                   false,
		Muted:                  false,
		ShowControls:           BoolPtr(true),
		Pip:                    BoolPtr(true),
		Airplay:                BoolPtr(true),
		Chromecast:             BoolPtr(true),
	}
}

func FindOrCreateUserPreference(ctx context.Context, db *gorm.DB, userID string) (*UserPreference, error) {
	var pref UserPreference
	if err := db.WithContext(ctx).Where("user_id = ?", userID).First(&pref).Error; err == nil {
		normalizeUserPreferenceDefaults(&pref)
		return &pref, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	pref = *DefaultUserPreference(userID)
	if err := db.WithContext(ctx).Create(&pref).Error; err != nil {
		return nil, err
	}
	return &pref, nil
}

func GetWalletBalance(ctx context.Context, db *gorm.DB, userID string) (float64, error) {
	var balance float64
	if err := db.WithContext(ctx).
		Model(&WalletTransaction{}).
		Where("user_id = ?", userID).
		Select("COALESCE(SUM(amount), 0)").
		Scan(&balance).Error; err != nil {
		return 0, err
	}
	return balance, nil
}

func GetLatestPlanSubscription(ctx context.Context, db *gorm.DB, userID string) (*PlanSubscription, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, gorm.ErrRecordNotFound
	}

	var subscription PlanSubscription
	if err := db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Order("id DESC").
		First(&subscription).Error; err != nil {
		return nil, err
	}

	return &subscription, nil
}

func IsSubscriptionExpiringSoon(expiresAt time.Time, now time.Time) bool {
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return false
	}
	return expiresAt.Sub(now) <= 7*24*time.Hour
}

func normalizeUserPreferenceDefaults(pref *UserPreference) {
	if pref == nil {
		return
	}
	if strings.TrimSpace(StringValue(pref.Language)) == "" {
		pref.Language = StringPtr(defaultPreferenceLanguage)
	}
	if strings.TrimSpace(StringValue(pref.Locale)) == "" {
		locale := StringValue(pref.Language)
		if strings.TrimSpace(locale) == "" {
			locale = defaultPreferenceLocale
		}
		pref.Locale = StringPtr(locale)
	}
	if pref.EmailNotifications == nil {
		pref.EmailNotifications = BoolPtr(true)
	}
	if pref.PushNotifications == nil {
		pref.PushNotifications = BoolPtr(true)
	}
	if pref.ShowControls == nil {
		pref.ShowControls = BoolPtr(true)
	}
	if pref.Pip == nil {
		pref.Pip = BoolPtr(true)
	}
	if pref.Airplay == nil {
		pref.Airplay = BoolPtr(true)
	}
	if pref.Chromecast == nil {
		pref.Chromecast = BoolPtr(true)
	}
}

func StringPtr(value string) *string {
	v := value
	return &v
}

func BoolPtr(value bool) *bool {
	v := value
	return &v
}

func StringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
