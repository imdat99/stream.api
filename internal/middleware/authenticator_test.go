package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
)

type testLogger struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
func (testLogger) Debug(string, ...any) {}
func (testLogger) Warn(string, ...any)  {}

func newAuthenticatorTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Dialector{DriverName: "sqlite", DSN: dsn}, &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE user (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			password TEXT,
			username TEXT,
			avatar TEXT,
			role TEXT NOT NULL,
			google_id TEXT,
			storage_used INTEGER NOT NULL DEFAULT 0,
			plan_id TEXT,
			referred_by_user_id TEXT,
			referral_eligible BOOLEAN NOT NULL DEFAULT 1,
			referral_reward_bps INTEGER,
			referral_reward_granted_at DATETIME,
			referral_reward_payment_id TEXT,
			referral_reward_amount REAL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1,
			telegram_id TEXT
		)`,
		`CREATE TABLE plan_subscriptions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			payment_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			term_months INTEGER NOT NULL,
			payment_method TEXT NOT NULL,
			wallet_amount REAL NOT NULL,
			topup_amount REAL NOT NULL,
			started_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			reminder_7d_sent_at DATETIME,
			reminder_3d_sent_at DATETIME,
			reminder_1d_sent_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE notifications (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			metadata TEXT,
			action_url TEXT,
			action_label TEXT,
			is_read BOOLEAN NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1
		)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("create sqlite schema: %v", err)
		}
	}
	query.SetDefault(db)
	return db
}

func newTrustedContext(userID, role string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		ActorMarkerMetadataKey, "trusted-marker",
		ActorIDMetadataKey, userID,
		ActorRoleMetadataKey, role,
		ActorEmailMetadataKey, "actor@example.com",
	))
}

func TestRequireActor(t *testing.T) {

	auth := NewAuthenticator(newAuthenticatorTestDB(t), testLogger{}, "trusted-marker", nil)

	t.Run("thiếu metadata", func(t *testing.T) {
		_, err := auth.RequireActor(context.Background())
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})

	t.Run("trusted marker sai", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(ActorMarkerMetadataKey, "wrong", ActorIDMetadataKey, "u1", ActorRoleMetadataKey, "USER"))
		_, err := auth.RequireActor(ctx)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})

	t.Run("thiếu actor id hoặc role", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(ActorMarkerMetadataKey, "trusted-marker", ActorIDMetadataKey, "u1"))
		_, err := auth.RequireActor(ctx)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})

	t.Run("actor hợp lệ", func(t *testing.T) {
		actor, err := auth.RequireActor(newTrustedContext("u1", "ADMIN"))
		if err != nil {
			t.Fatalf("RequireActor() error = %v", err)
		}
		if actor.UserID != "u1" || actor.Role != "ADMIN" || actor.Email != "actor@example.com" {
			t.Fatalf("actor = %#v", actor)
		}
	})
}

func TestAuthenticate(t *testing.T) {

	t.Run("user không tồn tại", func(t *testing.T) {
		db := newAuthenticatorTestDB(t)
		auth := NewAuthenticator(db, testLogger{}, "trusted-marker", nil)
		_, err := auth.Authenticate(newTrustedContext(uuid.NewString(), "USER"))
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})

	t.Run("user bị block", func(t *testing.T) {
		db := newAuthenticatorTestDB(t)
		blocked := model.User{ID: uuid.NewString(), Email: "blocked@example.com", Role: stringPtr("block")}
		if err := db.Create(&blocked).Error; err != nil {
			t.Fatalf("create blocked user: %v", err)
		}
		auth := NewAuthenticator(db, testLogger{}, "trusted-marker", nil)
		_, err := auth.Authenticate(newTrustedContext(blocked.ID, "USER"))
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
		}
	})

	t.Run("subscription active sync user.plan_id", func(t *testing.T) {
		db := newAuthenticatorTestDB(t)
		planID := uuid.NewString()
		user := model.User{ID: uuid.NewString(), Email: "active@example.com", Role: stringPtr("USER")}
		if err := db.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		subscription := model.PlanSubscription{
			ID:            uuid.NewString(),
			UserID:        user.ID,
			PaymentID:     uuid.NewString(),
			PlanID:        planID,
			TermMonths:    1,
			PaymentMethod: "wallet",
			WalletAmount:  10,
			TopupAmount:   0,
			StartedAt:     time.Now().UTC().Add(-24 * time.Hour),
			ExpiresAt:     time.Now().UTC().Add(10 * 24 * time.Hour),
		}
		if err := db.Create(&subscription).Error; err != nil {
			t.Fatalf("create subscription: %v", err)
		}
		auth := NewAuthenticator(db, testLogger{}, "trusted-marker", nil)

		result, err := auth.Authenticate(newTrustedContext(user.ID, "USER"))
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if result.User.PlanID == nil || *result.User.PlanID != planID {
			t.Fatalf("plan_id = %v, want %s", result.User.PlanID, planID)
		}
	})

	t.Run("subscription expired clear user.plan_id", func(t *testing.T) {
		db := newAuthenticatorTestDB(t)
		planID := uuid.NewString()
		user := model.User{ID: uuid.NewString(), Email: "expired@example.com", Role: stringPtr("USER"), PlanID: &planID}
		if err := db.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		subscription := model.PlanSubscription{
			ID:            uuid.NewString(),
			UserID:        user.ID,
			PaymentID:     uuid.NewString(),
			PlanID:        planID,
			TermMonths:    1,
			PaymentMethod: "wallet",
			WalletAmount:  10,
			TopupAmount:   0,
			StartedAt:     time.Now().UTC().Add(-10 * 24 * time.Hour),
			ExpiresAt:     time.Now().UTC().Add(-1 * time.Hour),
		}
		if err := db.Create(&subscription).Error; err != nil {
			t.Fatalf("create subscription: %v", err)
		}
		auth := NewAuthenticator(db, testLogger{}, "trusted-marker", nil)

		result, err := auth.Authenticate(newTrustedContext(user.ID, "USER"))
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if result.User.PlanID != nil {
			t.Fatalf("plan_id = %v, want nil", result.User.PlanID)
		}
	})

	t.Run("reminder chỉ tạo một lần theo threshold của latest subscription", func(t *testing.T) {
		tests := []struct {
			name      string
			expiresIn time.Duration
			wantDays  float64
			wantField string
		}{
			{name: "7 ngày", expiresIn: 6 * 24 * time.Hour, wantDays: 7, wantField: "reminder_7d_sent_at"},
			{name: "3 ngày", expiresIn: 2 * 24 * time.Hour, wantDays: 3, wantField: "reminder_3d_sent_at"},
			{name: "1 ngày", expiresIn: 12 * time.Hour, wantDays: 1, wantField: "reminder_1d_sent_at"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := newAuthenticatorTestDB(t)
				user := model.User{ID: uuid.NewString(), Email: "reminder@example.com", Role: stringPtr("USER")}
				if err := db.Create(&user).Error; err != nil {
					t.Fatalf("create user: %v", err)
				}

				now := time.Now().UTC()
				subscription := model.PlanSubscription{
					ID:            uuid.NewString(),
					UserID:        user.ID,
					PaymentID:     uuid.NewString(),
					PlanID:        uuid.NewString(),
					TermMonths:    1,
					PaymentMethod: "wallet",
					WalletAmount:  10,
					ExpiresAt:     now.Add(tt.expiresIn),
					StartedAt:     now.Add(-24 * time.Hour),
				}
				if err := db.Create(&subscription).Error; err != nil {
					t.Fatalf("create subscription: %v", err)
				}

				auth := NewAuthenticator(db, testLogger{}, "trusted-marker", nil)
				for range 2 {
					if _, err := auth.Authenticate(newTrustedContext(user.ID, "USER")); err != nil {
						t.Fatalf("Authenticate() error = %v", err)
					}
				}

				var notifications []model.Notification
				if err := db.Order("created_at ASC, id ASC").Find(&notifications, "user_id = ?", user.ID).Error; err != nil {
					t.Fatalf("list notifications: %v", err)
				}
				if len(notifications) != 1 {
					t.Fatalf("notification count = %d, want 1", len(notifications))
				}

				var payload map[string]any
				if err := json.Unmarshal([]byte(*notifications[0].Metadata), &payload); err != nil {
					t.Fatalf("unmarshal notification metadata: %v", err)
				}
				if payload["reminder_days"] != tt.wantDays {
					t.Fatalf("metadata reminder_days = %v, want %v", payload["reminder_days"], tt.wantDays)
				}

				var latest model.PlanSubscription
				if err := db.First(&latest, "id = ?", subscription.ID).Error; err != nil {
					t.Fatalf("load subscription: %v", err)
				}
				switch tt.wantField {
				case "reminder_7d_sent_at":
					if latest.Reminder7DSentAt == nil {
						t.Fatal("expected reminder_7d_sent_at to be set")
					}
				case "reminder_3d_sent_at":
					if latest.Reminder3DSentAt == nil {
						t.Fatal("expected reminder_3d_sent_at to be set")
					}
				case "reminder_1d_sent_at":
					if latest.Reminder1DSentAt == nil {
						t.Fatal("expected reminder_1d_sent_at to be set")
					}
				}
			})
		}
	})
}

func stringPtr(v string) *string { return &v }
