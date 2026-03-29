package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	_ "modernc.org/sqlite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/internal/middleware"
	"stream.api/internal/repository"
)

type serviceTestLogger struct{}

func (serviceTestLogger) Info(string, ...any)  {}
func (serviceTestLogger) Error(string, ...any) {}
func (serviceTestLogger) Debug(string, ...any) {}
func (serviceTestLogger) Warn(string, ...any)  {}

const notificationTestTrustedMarker = "trusted-notification-test-marker"

type publishedNotificationEvent struct {
	notification *model.Notification
}

type fakeNotificationEventPublisher struct {
	events []publishedNotificationEvent
}

func (f *fakeNotificationEventPublisher) PublishNotificationCreated(_ context.Context, notification *model.Notification) error {
	copyNotification := *notification
	f.events = append(f.events, publishedNotificationEvent{notification: &copyNotification})
	return nil
}

func newNotificationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Dialector{DriverName: "sqlite", DSN: dsn}, &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE user (id TEXT PRIMARY KEY,email TEXT NOT NULL,password TEXT,username TEXT,avatar TEXT,role TEXT NOT NULL,google_id TEXT,storage_used INTEGER NOT NULL DEFAULT 0,plan_id TEXT,referred_by_user_id TEXT,referral_eligible BOOLEAN NOT NULL DEFAULT 1,referral_reward_bps INTEGER,referral_reward_granted_at DATETIME,referral_reward_payment_id TEXT,referral_reward_amount REAL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,version INTEGER NOT NULL DEFAULT 1,telegram_id TEXT)`,
		`CREATE TABLE plan (id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT,price REAL NOT NULL,cycle TEXT NOT NULL,storage_limit INTEGER NOT NULL,upload_limit INTEGER NOT NULL,duration_limit INTEGER NOT NULL,quality_limit TEXT NOT NULL,features JSON,is_active BOOLEAN NOT NULL DEFAULT 1,version INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE payment (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,plan_id TEXT,amount REAL NOT NULL,currency TEXT,status TEXT,provider TEXT,transaction_id TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,version INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE plan_subscriptions (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,payment_id TEXT NOT NULL,plan_id TEXT NOT NULL,term_months INTEGER NOT NULL,payment_method TEXT NOT NULL,wallet_amount REAL NOT NULL,topup_amount REAL NOT NULL,started_at DATETIME NOT NULL,expires_at DATETIME NOT NULL,reminder_7d_sent_at DATETIME,reminder_3d_sent_at DATETIME,reminder_1d_sent_at DATETIME,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,version INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE wallet_transactions (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,type TEXT NOT NULL,amount REAL NOT NULL,currency TEXT,note TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,payment_id TEXT,plan_id TEXT,term_months INTEGER,version INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE notifications (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,type TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,metadata TEXT,action_url TEXT,action_label TEXT,is_read BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,version INTEGER NOT NULL DEFAULT 1)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("create test schema: %v", err)
		}
	}
	query.SetDefault(db)
	return db
}

func newNotificationTestServices(t *testing.T, db *gorm.DB, publisher NotificationEventPublisher) *appServices {
	t.Helper()
	return &appServices{
		db:                 db,
		logger:             serviceTestLogger{},
		authenticator:      middleware.NewAuthenticator(db, serviceTestLogger{}, notificationTestTrustedMarker, publisher),
		googleUserInfoURL:  defaultGoogleUserInfoURL,
		userRepository:     repository.NewUserRepository(db),
		planRepository:     repository.NewPlanRepository(db),
		paymentRepository:  repository.NewPaymentRepository(db),
		billingRepository:  repository.NewBillingRepository(db),
		notificationRepo:   repository.NewNotificationRepository(db),
		notificationEvents: publisher,
	}
}

func notificationTestContext(userID, role string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.ActorMarkerMetadataKey, notificationTestTrustedMarker,
		middleware.ActorIDMetadataKey, userID,
		middleware.ActorRoleMetadataKey, role,
		middleware.ActorEmailMetadataKey, "actor@example.com",
	))
}

func notificationPtrString(v string) *string { return &v }
func notificationPtrBool(v bool) *bool { return &v }
func notificationPtrFloat64(v float64) *float64 { return &v }

func seedNotificationUser(t *testing.T, db *gorm.DB, user model.User) model.User {
	t.Helper()
	if user.Role == nil {
		user.Role = notificationPtrString("USER")
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func seedNotificationPlan(t *testing.T, db *gorm.DB, plan model.Plan) model.Plan {
	t.Helper()
	if plan.IsActive == nil {
		plan.IsActive = notificationPtrBool(true)
	}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}
	return plan
}

func seedNotificationWalletTransaction(t *testing.T, db *gorm.DB, tx model.WalletTransaction) model.WalletTransaction {
	t.Helper()
	if err := db.Create(&tx).Error; err != nil {
		t.Fatalf("create wallet transaction: %v", err)
	}
	return tx
}

func TestExecutePaymentFlowPublishesNotificationEvent(t *testing.T) {
	db := newNotificationTestDB(t)
	publisher := &fakeNotificationEventPublisher{}
	services := newNotificationTestServices(t, db, publisher)

	user := seedNotificationUser(t, db, model.User{ID: uuid.NewString(), Email: "payer@example.com", Role: notificationPtrString("USER")})
	plan := seedNotificationPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 10, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: notificationPtrBool(true)})
	seedNotificationWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: walletTransactionTypeTopup, Amount: 5, Currency: notificationPtrString("USD")})

	_, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: user.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodTopup, TopupAmount: notificationPtrFloat64(5)})
	if err != nil {
		t.Fatalf("executePaymentFlow() error = %v", err)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("published events = %d, want 1", len(publisher.events))
	}
	if publisher.events[0].notification == nil || publisher.events[0].notification.Type != "billing.subscription" {
		t.Fatalf("published notification = %#v", publisher.events[0].notification)
	}
}

func TestTopupWalletPublishesNotificationEvent(t *testing.T) {
	db := newNotificationTestDB(t)
	publisher := &fakeNotificationEventPublisher{}
	services := newNotificationTestServices(t, db, publisher)
	user := seedNotificationUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: notificationPtrString("USER")})

	_, err := (&paymentsAppService{appServices: services}).TopupWallet(notificationTestContext(user.ID, "USER"), &appv1.TopupWalletRequest{Amount: 12})
	if err != nil {
		t.Fatalf("TopupWallet() error = %v", err)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("published events = %d, want 1", len(publisher.events))
	}
	if publisher.events[0].notification == nil || publisher.events[0].notification.Type != "billing.topup" {
		t.Fatalf("published notification = %#v", publisher.events[0].notification)
	}
}

func TestBuildNotificationCreatedPayload(t *testing.T) {
	now := time.Now().UTC()
	notification := &model.Notification{ID: uuid.NewString(), UserID: uuid.NewString(), Type: "billing.subscription", Title: "Subscription activated", Message: "Your subscription is active.", ActionURL: notificationPtrString("/settings/billing"), ActionLabel: notificationPtrString("Renew plan"), CreatedAt: &now}
	payload := BuildNotificationCreatedPayload(notification)
	if payload.ID != notification.ID || payload.UserID != notification.UserID || payload.Type != notification.Type {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.CreatedAt == "" {
		t.Fatal("payload created_at should not be empty")
	}
}
