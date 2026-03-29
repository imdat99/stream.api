package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/internal/middleware"
	"stream.api/internal/repository"
	"stream.api/pkg/logger"
)

const popupTestTrustedMarker = "trusted-popup-test-marker"

type popupTestLogger struct{}

func (popupTestLogger) Info(string, ...any)  {}
func (popupTestLogger) Error(string, ...any) {}
func (popupTestLogger) Debug(string, ...any) {}
func (popupTestLogger) Warn(string, ...any)  {}

func newPopupTestDB(t *testing.T) *gorm.DB {
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
		`CREATE TABLE plan (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			price REAL NOT NULL,
			cycle TEXT NOT NULL,
			storage_limit INTEGER NOT NULL,
			upload_limit INTEGER NOT NULL,
			duration_limit INTEGER NOT NULL,
			quality_limit TEXT NOT NULL,
			features JSON,
			is_active BOOLEAN NOT NULL DEFAULT 1,
			version INTEGER NOT NULL DEFAULT 1
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
		`CREATE TABLE popup_ads (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			label TEXT NOT NULL,
			value TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT 1,
			max_triggers_per_session INTEGER NOT NULL DEFAULT 3,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1
		)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("create test schema: %v", err)
		}
	}

	query.SetDefault(db)
	return db
}

func newPopupTestServices(t *testing.T, db *gorm.DB) *appServices {
	t.Helper()
	return &appServices{
		db:                db,
		logger:            popupTestLogger{},
		authenticator:     middleware.NewAuthenticator(db, popupTestLogger{}, popupTestTrustedMarker, nil),
		userRepository:    repository.NewUserRepository(db),
		planRepository:    repository.NewPlanRepository(db),
		notificationRepo:  repository.NewNotificationRepository(db),
		popupAdRepository: repository.NewPopupAdRepository(db),
		googleUserInfoURL: defaultGoogleUserInfoURL,
	}
}

func popupTestContext(userID, role string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.ActorMarkerMetadataKey, popupTestTrustedMarker,
		middleware.ActorIDMetadataKey, userID,
		middleware.ActorRoleMetadataKey, role,
		middleware.ActorEmailMetadataKey, "actor@example.com",
	))
}

func popupPtrString(v string) *string { return &v }
func popupPtrBool(v bool) *bool { return &v }
func popupPtrInt32(v int32) *int32 { return &v }
func popupPtrTime(v time.Time) *time.Time { return &v }

func popupSeedUser(t *testing.T, db *gorm.DB, user model.User) model.User {
	t.Helper()
	if user.Role == nil {
		user.Role = popupPtrString("USER")
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func popupSeedAd(t *testing.T, db *gorm.DB, item model.PopupAd) model.PopupAd {
	t.Helper()
	if item.IsActive == nil {
		item.IsActive = popupPtrBool(true)
	}
	if *item.MaxTriggersPerSession == 0 {
		*item.MaxTriggersPerSession = 60
	}
	if item.CreatedAt == nil {
		now := time.Now().UTC()
		item.CreatedAt = &now
	}
	if err := db.Create(&item).Error; err != nil {
		t.Fatalf("create popup ad: %v", err)
	}
	return item
}

func popupMustListAds(t *testing.T, db *gorm.DB, userID string) []model.PopupAd {
	t.Helper()
	var items []model.PopupAd
	if err := db.Order("created_at DESC").Find(&items, "user_id = ?", userID).Error; err != nil {
		t.Fatalf("list popup ads: %v", err)
	}
	return items
}

func popupAssertGRPCCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("grpc code = %v, want %v (err=%v)", status.Code(err), code, err)
	}
}

func TestPopupAdsUserFlow(t *testing.T) {
	t.Run("create list update delete popup ad", func(t *testing.T) {
		db := newPopupTestDB(t)
		services := newPopupTestServices(t, db)
		user := popupSeedUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: popupPtrString("USER")})

		createResp, err := (&popupAdsAppService{appServices: services}).CreatePopupAd(popupTestContext(user.ID, "USER"), &appv1.CreatePopupAdRequest{
			Type:                 "url",
			Label:                "Homepage Campaign",
			Value:                "https://example.com/landing",
			IsActive:             popupPtrBool(true),
			MaxTriggersPerSession: popupPtrInt32(5),
		})
		if err != nil {
			t.Fatalf("CreatePopupAd() error = %v", err)
		}
		if createResp.Item == nil || createResp.Item.Label != "Homepage Campaign" {
			t.Fatalf("CreatePopupAd() unexpected response: %#v", createResp)
		}

		listResp, err := (&popupAdsAppService{appServices: services}).ListPopupAds(popupTestContext(user.ID, "USER"), &appv1.ListPopupAdsRequest{})
		if err != nil {
			t.Fatalf("ListPopupAds() error = %v", err)
		}
		if len(listResp.Items) != 1 {
			t.Fatalf("ListPopupAds() count = %d, want 1", len(listResp.Items))
		}

		updateResp, err := (&popupAdsAppService{appServices: services}).UpdatePopupAd(popupTestContext(user.ID, "USER"), &appv1.UpdatePopupAdRequest{
			Id:                   createResp.Item.Id,
			Type:                 "script",
			Label:                "Homepage Campaign v2",
			Value:                `<script async src="//example.com/ad.js"></script>`,
			IsActive:             popupPtrBool(false),
			MaxTriggersPerSession: popupPtrInt32(8),
		})
		if err != nil {
			t.Fatalf("UpdatePopupAd() error = %v", err)
		}
		if updateResp.Item == nil || updateResp.Item.Label != "Homepage Campaign v2" || updateResp.Item.IsActive {
			t.Fatalf("UpdatePopupAd() unexpected response: %#v", updateResp)
		}

		items := popupMustListAds(t, db, user.ID)
		if len(items) != 1 {
			t.Fatalf("popup ad count = %d, want 1", len(items))
		}
		if items[0].Type != "script" || items[0].Label != "Homepage Campaign v2" || *items[0].MaxTriggersPerSession != 8 {
			t.Fatalf("popup ad values = %#v", items[0])
		}

		_, err = (&popupAdsAppService{appServices: services}).DeletePopupAd(popupTestContext(user.ID, "USER"), &appv1.DeletePopupAdRequest{Id: createResp.Item.Id})
		if err != nil {
			t.Fatalf("DeletePopupAd() error = %v", err)
		}
		items = popupMustListAds(t, db, user.ID)
		if len(items) != 0 {
			t.Fatalf("popup ad count after delete = %d, want 0", len(items))
		}
	})

	t.Run("reject invalid type", func(t *testing.T) {
		db := newPopupTestDB(t)
		services := newPopupTestServices(t, db)
		user := popupSeedUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: popupPtrString("USER")})

		_, err := (&popupAdsAppService{appServices: services}).CreatePopupAd(popupTestContext(user.ID, "USER"), &appv1.CreatePopupAdRequest{
			Type:  "image",
			Label: "Invalid",
			Value: "https://example.com/landing",
		})
		popupAssertGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("get active popup ad returns newest active item", func(t *testing.T) {
		db := newPopupTestDB(t)
		services := newPopupTestServices(t, db)
		user := popupSeedUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: popupPtrString("USER")})
		popupSeedAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Type: "url", Label: "inactive", Value: "https://example.com/1", IsActive: popupPtrBool(false), MaxTriggersPerSession: popupPtrInt32(2)})
		popupSeedAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Type: "url", Label: "older", Value: "https://example.com/3", IsActive: popupPtrBool(true), MaxTriggersPerSession: popupPtrInt32(1), CreatedAt: popupPtrTime(time.Now().UTC().Add(-time.Minute))})
		winner := popupSeedAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Type: "script", Label: "winner", Value: `<script async src="//example.com/win.js"></script>`, IsActive: popupPtrBool(true), MaxTriggersPerSession: popupPtrInt32(3), CreatedAt: popupPtrTime(time.Now().UTC())})

		resp, err := (&popupAdsAppService{appServices: services}).GetActivePopupAd(popupTestContext(user.ID, "USER"), &appv1.GetActivePopupAdRequest{})
		if err != nil {
			t.Fatalf("GetActivePopupAd() error = %v", err)
		}
		if resp.Item == nil || resp.Item.Id != winner.ID {
			t.Fatalf("GetActivePopupAd() = %#v, want winner %q", resp.Item, winner.ID)
		}
	})
}

func TestPopupAdsAdminFlow(t *testing.T) {
	t.Run("admin create list update delete popup ad", func(t *testing.T) {
		db := newPopupTestDB(t)
		services := newPopupTestServices(t, db)
		admin := popupSeedUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: popupPtrString("ADMIN")})
		user := popupSeedUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: popupPtrString("USER")})

		createResp, err := services.CreateAdminPopupAd(popupTestContext(admin.ID, "ADMIN"), &appv1.CreateAdminPopupAdRequest{
			UserId:               user.ID,
			Type:                 "url",
			Label:                "Admin Campaign",
			Value:                "https://example.com/admin",
			IsActive:             popupPtrBool(true),
			MaxTriggersPerSession: popupPtrInt32(7),
		})
		if err != nil {
			t.Fatalf("CreateAdminPopupAd() error = %v", err)
		}
		if createResp.Item == nil || createResp.Item.UserId != user.ID {
			t.Fatalf("CreateAdminPopupAd() unexpected response: %#v", createResp)
		}

		listResp, err := services.ListAdminPopupAds(popupTestContext(admin.ID, "ADMIN"), &appv1.ListAdminPopupAdsRequest{UserId: &user.ID})
		if err != nil {
			t.Fatalf("ListAdminPopupAds() error = %v", err)
		}
		if len(listResp.Items) != 1 {
			t.Fatalf("ListAdminPopupAds() count = %d, want 1", len(listResp.Items))
		}

		updateResp, err := services.UpdateAdminPopupAd(popupTestContext(admin.ID, "ADMIN"), &appv1.UpdateAdminPopupAdRequest{
			Id:                   createResp.Item.Id,
			UserId:               user.ID,
			Type:                 "script",
			Label:                "Admin Campaign v2",
			Value:                `<script async src="//example.com/admin-v2.js"></script>`,
			IsActive:             popupPtrBool(false),
			MaxTriggersPerSession: popupPtrInt32(11),
		})
		if err != nil {
			t.Fatalf("UpdateAdminPopupAd() error = %v", err)
		}
		if updateResp.Item == nil || updateResp.Item.Label != "Admin Campaign v2" || updateResp.Item.IsActive {
			t.Fatalf("UpdateAdminPopupAd() unexpected response: %#v", updateResp)
		}

		_, err = services.DeleteAdminPopupAd(popupTestContext(admin.ID, "ADMIN"), &appv1.DeleteAdminPopupAdRequest{Id: createResp.Item.Id})
		if err != nil {
			t.Fatalf("DeleteAdminPopupAd() error = %v", err)
		}
		items := popupMustListAds(t, db, user.ID)
		if len(items) != 0 {
			t.Fatalf("popup ad count after delete = %d, want 0", len(items))
		}
	})
}

var _ logger.Logger = popupTestLogger{}
