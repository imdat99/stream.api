package model

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
)

// BoolPtr returns a pointer to the given bool value
func BoolPtr(b bool) *bool {
	return &b
}

// StringPtr returns a pointer to the given string value
func StringPtr(s string) *string {
	return &s
}

// StringValue returns the string value or empty string if nil
func StringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// BoolValue returns the bool value or false if nil
func BoolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// Int64Ptr returns a pointer to the given int64 value
func Int64Ptr(i int64) *int64 {
	return &i
}

// Float64Ptr returns a pointer to the given float64 value
func Float64Ptr(f float64) *float64 {
	return &f
}

// TimePtr returns a pointer to the given time.Time value
func TimePtr(t time.Time) *time.Time {
	return &t
}

// FindOrCreateUserPreference finds or creates a user preference record
func FindOrCreateUserPreference(ctx context.Context, db *gorm.DB, userID string) (*UserPreference, error) {
	pref := &UserPreference{}
	err := db.WithContext(ctx).
		Where("user_id = ?", userID).
		Attrs(&UserPreference{
			Language:               StringPtr("en"),
			Locale:                 StringPtr("en"),
			EmailNotifications:     BoolPtr(true),
			PushNotifications:      BoolPtr(true),
			MarketingNotifications: false,
			TelegramNotifications:  false,
		}).
		FirstOrCreate(pref).Error

	// Handle race condition: if duplicate key error, fetch the existing record
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		err = db.WithContext(ctx).Where("user_id = ?", userID).First(pref).Error
	}

	return pref, err
}

// GetWalletBalance calculates the current wallet balance for a user
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

// GetLatestPlanSubscription finds the latest plan subscription for a user
func GetLatestPlanSubscription(ctx context.Context, db *gorm.DB, userID string) (*PlanSubscription, error) {
	sub := &PlanSubscription{}
	err := db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("expires_at DESC").
		First(sub).Error
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// IsSubscriptionExpiringSoon checks if subscription expires within threshold days
func IsSubscriptionExpiringSoon(sub *PlanSubscription, thresholdDays int) bool {
	if sub == nil {
		return false
	}
	now := time.Now()
	hoursUntilExpiry := sub.ExpiresAt.Sub(now).Hours()
	thresholdHours := float64(thresholdDays) * 24
	return hoursUntilExpiry > 0 && hoursUntilExpiry <= thresholdHours
}
