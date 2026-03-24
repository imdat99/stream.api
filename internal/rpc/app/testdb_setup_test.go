package app

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/middleware"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/token"
)

const testTrustedMarker = "trusted-test-marker"

var testBufDialerListenerSize = 1024 * 1024

type testLogger struct{}

type fakeCache struct {
	values map[string]string
}

type fakeTokenProvider struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
func (testLogger) Debug(string, ...any) {}
func (testLogger) Warn(string, ...any)  {}

func (f *fakeCache) Set(_ context.Context, key string, value interface{}, _ time.Duration) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = fmt.Sprint(value)
	return nil
}

func (f *fakeCache) Get(_ context.Context, key string) (string, error) {
	if f.values == nil {
		return "", fmt.Errorf("cache miss")
	}
	value, ok := f.values[key]
	if !ok {
		return "", fmt.Errorf("cache miss")
	}
	return value, nil
}

func (f *fakeCache) Del(_ context.Context, key string) error {
	delete(f.values, key)
	return nil
}

func (f *fakeCache) Close() error {
	return nil
}

func (fakeTokenProvider) GenerateTokenPair(userID, _, _ string) (*token.TokenPair, error) {
	return &token.TokenPair{
		AccessToken:  "access-" + userID,
		RefreshToken: "refresh-" + userID,
		AccessUUID:   "access-uuid-" + userID,
		RefreshUUID:  "refresh-uuid-" + userID,
		AtExpires:    time.Now().Add(time.Hour).Unix(),
		RtExpires:    time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

func (fakeTokenProvider) ParseToken(tokenString string) (*token.Claims, error) {
	return &token.Claims{UserID: tokenString}, nil
}

func (fakeTokenProvider) ParseMapToken(tokenString string) (map[string]interface{}, error) {
	return map[string]interface{}{"token": tokenString}, nil
}

var _ cache.Cache = (*fakeCache)(nil)
var _ token.Provider = fakeTokenProvider{}

func newTestDB(t *testing.T) *gorm.DB {
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
		`CREATE TABLE payment (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			plan_id TEXT,
			amount REAL NOT NULL,
			currency TEXT,
			status TEXT,
			provider TEXT,
			transaction_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
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
		`CREATE TABLE wallet_transactions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			amount REAL NOT NULL,
			currency TEXT,
			note TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			payment_id TEXT,
			plan_id TEXT,
			term_months INTEGER,
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
		`CREATE TABLE user_preferences (
			user_id TEXT PRIMARY KEY,
			language TEXT NOT NULL DEFAULT 'en',
			locale TEXT NOT NULL DEFAULT 'en',
			email_notifications BOOLEAN NOT NULL DEFAULT 1,
			push_notifications BOOLEAN NOT NULL DEFAULT 1,
			marketing_notifications BOOLEAN NOT NULL DEFAULT 0,
			telegram_notifications BOOLEAN NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE player_configs (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			autoplay BOOLEAN NOT NULL DEFAULT 0,
			loop BOOLEAN NOT NULL DEFAULT 0,
			muted BOOLEAN NOT NULL DEFAULT 0,
			show_controls BOOLEAN NOT NULL DEFAULT 1,
			pip BOOLEAN NOT NULL DEFAULT 1,
			airplay BOOLEAN NOT NULL DEFAULT 1,
			chromecast BOOLEAN NOT NULL DEFAULT 1,
			is_active BOOLEAN NOT NULL DEFAULT 1,
			is_default BOOLEAN NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			version INTEGER NOT NULL DEFAULT 1,
			encrytion_m3u8 BOOLEAN NOT NULL DEFAULT 1,
			logo_url TEXT
		)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("create test schema: %v", err)
		}
	}

	query.SetDefault(db)
	return db
}

func newTestAppServices(t *testing.T, db *gorm.DB) *appServices {
	t.Helper()

	if db == nil {
		db = newTestDB(t)
	}

	return &appServices{
		db:                db,
		logger:            testLogger{},
		authenticator:     middleware.NewAuthenticator(db, testLogger{}, testTrustedMarker),
		cache:             &fakeCache{values: map[string]string{}},
		tokenProvider:     fakeTokenProvider{},
		googleUserInfoURL: defaultGoogleUserInfoURL,
	}
}

func newTestGRPCServer(t *testing.T, services *appServices) (*grpc.ClientConn, func()) {
	t.Helper()

	lis := bufconn.Listen(testBufDialerListenerSize)
	server := grpc.NewServer()
	Register(server, &Services{
		AuthServiceServer:          services,
		AccountServiceServer:       services,
		PreferencesServiceServer:   services,
		UsageServiceServer:         services,
		NotificationsServiceServer: services,
		DomainsServiceServer:       services,
		AdTemplatesServiceServer:   services,
		PlayerConfigsServiceServer: services,
		PlansServiceServer:         services,
		PaymentsServiceServer:      services,
		VideosServiceServer:        services,
		AdminServiceServer:         services,
	})

	go func() {
		_ = server.Serve(lis)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	cancel()
	if err != nil {
		server.Stop()
		_ = lis.Close()
		t.Fatalf("dial bufconn: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		server.Stop()
		_ = lis.Close()
	}

	return conn, cleanup
}

func ptrFloat64(v float64) *float64 { return &v }
func ptrString(v string) *string    { return &v }
func ptrBool(v bool) *bool          { return &v }
func ptrInt64(v int64) *int64       { return &v }

func firstTestMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func seedTestUser(t *testing.T, db *gorm.DB, user model.User) model.User {
	t.Helper()
	if user.Role == nil {
		user.Role = ptrString("USER")
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func seedTestPlan(t *testing.T, db *gorm.DB, plan model.Plan) model.Plan {
	t.Helper()
	if plan.IsActive == nil {
		plan.IsActive = ptrBool(true)
	}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}
	return plan
}

func seedWalletTransaction(t *testing.T, db *gorm.DB, tx model.WalletTransaction) model.WalletTransaction {
	t.Helper()
	if err := db.Create(&tx).Error; err != nil {
		t.Fatalf("create wallet transaction: %v", err)
	}
	return tx
}

func seedSubscription(t *testing.T, db *gorm.DB, subscription model.PlanSubscription) model.PlanSubscription {
	t.Helper()
	if err := db.Create(&subscription).Error; err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	return subscription
}

func mustLoadUser(t *testing.T, db *gorm.DB, userID string) model.User {
	t.Helper()
	var user model.User
	if err := db.First(&user, "id = ?", userID).Error; err != nil {
		t.Fatalf("load user %s: %v", userID, err)
	}
	return user
}

func mustLoadPayment(t *testing.T, db *gorm.DB, paymentID string) model.Payment {
	t.Helper()
	var payment model.Payment
	if err := db.First(&payment, "id = ?", paymentID).Error; err != nil {
		t.Fatalf("load payment %s: %v", paymentID, err)
	}
	return payment
}

func mustLoadSubscriptionByPayment(t *testing.T, db *gorm.DB, paymentID string) model.PlanSubscription {
	t.Helper()
	var subscription model.PlanSubscription
	if err := db.First(&subscription, "payment_id = ?", paymentID).Error; err != nil {
		t.Fatalf("load subscription for payment %s: %v", paymentID, err)
	}
	return subscription
}

func mustListWalletTransactionsByPayment(t *testing.T, db *gorm.DB, paymentID string) []model.WalletTransaction {
	t.Helper()
	var items []model.WalletTransaction
	if err := db.Order("amount DESC").Find(&items, "payment_id = ?", paymentID).Error; err != nil {
		t.Fatalf("list wallet transactions for payment %s: %v", paymentID, err)
	}
	return items
}

func mustListNotificationsByUser(t *testing.T, db *gorm.DB, userID string) []model.Notification {
	t.Helper()
	var items []model.Notification
	if err := db.Order("created_at ASC, id ASC").Find(&items, "user_id = ?", userID).Error; err != nil {
		t.Fatalf("list notifications for user %s: %v", userID, err)
	}
	return items
}

func newPaymentsClient(conn *grpc.ClientConn) appv1.PaymentsServiceClient {
	return appv1.NewPaymentsServiceClient(conn)
}

func newAdminClient(conn *grpc.ClientConn) appv1.AdminServiceClient {
	return appv1.NewAdminServiceClient(conn)
}

var _ logger.Logger = testLogger{}
