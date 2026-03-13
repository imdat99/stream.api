package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type UserPayload struct {
	ID                string     `json:"id"`
	Email             string     `json:"email"`
	Username          *string    `json:"username,omitempty"`
	Avatar            *string    `json:"avatar,omitempty"`
	Role              *string    `json:"role,omitempty"`
	GoogleID          *string    `json:"google_id,omitempty"`
	StorageUsed       int64      `json:"storage_used"`
	PlanID            *string    `json:"plan_id,omitempty"`
	PlanStartedAt     *time.Time `json:"plan_started_at,omitempty"`
	PlanExpiresAt     *time.Time `json:"plan_expires_at,omitempty"`
	PlanTermMonths    *int32     `json:"plan_term_months,omitempty"`
	PlanPaymentMethod *string    `json:"plan_payment_method,omitempty"`
	PlanExpiringSoon  bool       `json:"plan_expiring_soon"`
	WalletBalance     float64    `json:"wallet_balance"`
	Language          string     `json:"language"`
	Locale            string     `json:"locale"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func BuildUserPayload(ctx context.Context, db *gorm.DB, user *model.User) (*UserPayload, error) {
	pref, err := model.FindOrCreateUserPreference(ctx, db, user.ID)
	if err != nil {
		return nil, err
	}

	walletBalance, err := model.GetWalletBalance(ctx, db, user.ID)
	if err != nil {
		return nil, err
	}

	language := strings.TrimSpace(model.StringValue(pref.Language))
	if language == "" {
		language = "en"
	}
	locale := strings.TrimSpace(model.StringValue(pref.Locale))
	if locale == "" {
		locale = language
	}

	effectivePlanID := user.PlanID
	var planStartedAt *time.Time
	var planExpiresAt *time.Time
	var planTermMonths *int32
	var planPaymentMethod *string
	planExpiringSoon := false
	now := time.Now().UTC()

	subscription, err := model.GetLatestPlanSubscription(ctx, db, user.ID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if err == nil {
		startedAt := subscription.StartedAt.UTC()
		expiresAt := subscription.ExpiresAt.UTC()
		termMonths := subscription.TermMonths
		paymentMethod := normalizePlanPaymentMethod(subscription.PaymentMethod)

		planStartedAt = &startedAt
		planExpiresAt = &expiresAt
		planTermMonths = &termMonths
		planPaymentMethod = &paymentMethod

		if expiresAt.After(now) {
			effectivePlanID = &subscription.PlanID
			planExpiringSoon = model.IsSubscriptionExpiringSoon(expiresAt, now)
		} else {
			effectivePlanID = nil
		}
	}

	return &UserPayload{
		ID:                user.ID,
		Email:             user.Email,
		Username:          user.Username,
		Avatar:            user.Avatar,
		Role:              user.Role,
		GoogleID:          user.GoogleID,
		StorageUsed:       user.StorageUsed,
		PlanID:            effectivePlanID,
		PlanStartedAt:     planStartedAt,
		PlanExpiresAt:     planExpiresAt,
		PlanTermMonths:    planTermMonths,
		PlanPaymentMethod: planPaymentMethod,
		PlanExpiringSoon:  planExpiringSoon,
		WalletBalance:     walletBalance,
		Language:          language,
		Locale:            locale,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}, nil
}

func normalizePlanPaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "topup":
		return "topup"
	default:
		return "wallet"
	}
}
