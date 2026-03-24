package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
)

const (
	ActorMarkerMetadataKey = "x-stream-internal-auth"
	ActorIDMetadataKey     = "x-stream-actor-id"
	ActorEmailMetadataKey  = "x-stream-actor-email"
	ActorRoleMetadataKey   = "x-stream-actor-role"
)

type AuthResult struct {
	UserID string
	User   *model.User
}

type Actor struct {
	UserID string
	Email  string
	Role   string
}

type Authenticator struct {
	db            *gorm.DB
	logger        logger.Logger
	trustedMarker string
}

func NewAuthenticator(db *gorm.DB, l logger.Logger, trustedMarker string) *Authenticator {
	return &Authenticator{
		db:            db,
		logger:        l,
		trustedMarker: strings.TrimSpace(trustedMarker),
	}
}

func (a *Authenticator) Authenticate(ctx context.Context) (*AuthResult, error) {
	actor, err := a.RequireActor(ctx)
	if err != nil {
		return nil, err
	}

	u := query.User
	user, err := u.WithContext(ctx).Where(u.ID.Eq(actor.UserID)).First()
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Unauthorized")
	}

	user, err = a.applyPostAuthSubscriptionState(ctx, user)
	if err != nil {
		a.logger.Error("Failed to sync subscription state", "error", err, "user_id", actor.UserID)
		return nil, status.Error(codes.Internal, "Failed to load user subscription state")
	}

	if user.Role != nil && strings.EqualFold(strings.TrimSpace(*user.Role), "block") {
		return nil, status.Error(codes.PermissionDenied, "Forbidden: User is blocked")
	}

	return &AuthResult{
		UserID: user.ID,
		User:   user,
	}, nil
}

func (a *Authenticator) RequireActor(ctx context.Context) (*Actor, error) {
	md, err := a.RequireTrustedMetadata(ctx)
	if err != nil {
		return nil, err
	}

	userID := strings.TrimSpace(firstMetadataValue(md, ActorIDMetadataKey))
	role := strings.TrimSpace(firstMetadataValue(md, ActorRoleMetadataKey))
	if userID == "" || role == "" {
		return nil, status.Error(codes.Unauthenticated, "Missing actor identity")
	}

	return &Actor{
		UserID: userID,
		Email:  strings.TrimSpace(firstMetadataValue(md, ActorEmailMetadataKey)),
		Role:   role,
	}, nil
}

func (a *Authenticator) RequireInternalCall(ctx context.Context) error {
	_, err := a.RequireTrustedMetadata(ctx)
	return err
}

func (a *Authenticator) RequireTrustedMetadata(ctx context.Context) (metadata.MD, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Missing actor metadata")
	}

	marker := firstMetadataValue(md, ActorMarkerMetadataKey)
	if marker == "" || marker != a.trustedMarker {
		return nil, status.Error(codes.Unauthenticated, "Invalid internal auth marker")
	}

	return md, nil
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (a *Authenticator) applyPostAuthSubscriptionState(ctx context.Context, user *model.User) (*model.User, error) {
	subscription, err := a.loadLatestSubscriptionForPostAuth(ctx, user)
	if err != nil {
		return nil, err
	}
	if subscription == nil {
		return user, nil
	}

	now := time.Now().UTC()
	if err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedSubscription, err := a.lockSubscriptionForPostAuth(ctx, tx, subscription.ID)
		if err != nil {
			return err
		}
		if lockedSubscription.ExpiresAt.After(now) {
			return a.applyActiveSubscriptionPostAuth(ctx, tx, user, lockedSubscription, now)
		}
		return a.clearExpiredPlanPostAuth(ctx, tx, user)
	}); err != nil {
		return nil, err
	}

	return user, nil
}

func (a *Authenticator) loadLatestSubscriptionForPostAuth(ctx context.Context, user *model.User) (*model.PlanSubscription, error) {
	subscription, err := model.GetLatestPlanSubscription(ctx, a.db, user.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return subscription, nil
}

func (a *Authenticator) lockSubscriptionForPostAuth(ctx context.Context, tx *gorm.DB, subscriptionID string) (*model.PlanSubscription, error) {
	var lockedSubscription model.PlanSubscription
	if err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", subscriptionID).
		First(&lockedSubscription).Error; err != nil {
		return nil, err
	}
	return &lockedSubscription, nil
}

func (a *Authenticator) applyActiveSubscriptionPostAuth(ctx context.Context, tx *gorm.DB, user *model.User, subscription *model.PlanSubscription, now time.Time) error {
	if user.PlanID == nil || strings.TrimSpace(*user.PlanID) != subscription.PlanID {
		if err := tx.WithContext(ctx).
			Model(&model.User{}).
			Where("id = ?", user.ID).
			Update("plan_id", subscription.PlanID).Error; err != nil {
			return err
		}
		user.PlanID = &subscription.PlanID
	}

	return a.maybeCreateSubscriptionReminderPostAuth(ctx, tx, user, subscription, now)
}

func (a *Authenticator) maybeCreateSubscriptionReminderPostAuth(ctx context.Context, tx *gorm.DB, user *model.User, subscription *model.PlanSubscription, now time.Time) error {
	reminderDays, reminderField := reminderFieldForSubscription(subscription, now)
	if reminderField == "" {
		return nil
	}

	sentAt := now
	notification := &model.Notification{
		ID:          uuidString(),
		UserID:      user.ID,
		Type:        "billing.subscription_expiring",
		Title:       "Plan expiring soon",
		Message:     reminderMessage(reminderDays),
		ActionURL:   model.StringPtr("/settings/billing"),
		ActionLabel: model.StringPtr("Renew plan"),
		Metadata: model.StringPtr(mustMarshalAuthJSON(map[string]any{
			"plan_id":       subscription.PlanID,
			"expires_at":    subscription.ExpiresAt.UTC().Format(time.RFC3339),
			"reminder_days": reminderDays,
		})),
	}
	if err := tx.WithContext(ctx).Create(notification).Error; err != nil {
		return err
	}
	return tx.WithContext(ctx).
		Model(&model.PlanSubscription{}).
		Where("id = ?", subscription.ID).
		Update(reminderField, sentAt).Error
}

func (a *Authenticator) clearExpiredPlanPostAuth(ctx context.Context, tx *gorm.DB, user *model.User) error {
	if user.PlanID == nil || strings.TrimSpace(*user.PlanID) == "" {
		return nil
	}
	if err := tx.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", user.ID).
		Update("plan_id", nil).Error; err != nil {
		return err
	}
	user.PlanID = nil
	return nil
}

func reminderFieldForSubscription(subscription *model.PlanSubscription, now time.Time) (int, string) {
	if subscription == nil || !subscription.ExpiresAt.After(now) {
		return 0, ""
	}

	remaining := subscription.ExpiresAt.Sub(now)
	switch {
	case remaining <= 24*time.Hour:
		if subscription.Reminder1DSentAt == nil {
			return 1, "reminder_1d_sent_at"
		}
	case remaining <= 72*time.Hour:
		if subscription.Reminder3DSentAt == nil {
			return 3, "reminder_3d_sent_at"
		}
	case remaining <= 7*24*time.Hour:
		if subscription.Reminder7DSentAt == nil {
			return 7, "reminder_7d_sent_at"
		}
	}

	return 0, ""
}

func reminderMessage(days int) string {
	switch days {
	case 1:
		return "Your current plan expires in 1 day. Renew now to avoid interruption."
	case 3:
		return "Your current plan expires in 3 days. Renew now to keep access active."
	default:
		return "Your current plan expires in 7 days. Renew now to keep your plan active."
	}
}

func mustMarshalAuthJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func uuidString() string {
	return uuid.New().String()
}
