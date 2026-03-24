package app

import (
	"context"
	"testing"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func TestRegisterReferralCapture(t *testing.T) {
	t.Run("register với ref hợp lệ lưu referred_by_user_id", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		referrer := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "ref@example.com", Username: ptrString("alice"), Role: ptrString("USER")})

		resp, err := services.Register(context.Background(), &appv1.RegisterRequest{
			Username:    "bob",
			Email:       "bob@example.com",
			Password:    "secret123",
			RefUsername: ptrString("alice"),
		})
		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}
		if resp.User == nil {
			t.Fatal("Register() user is nil")
		}
		created := mustLoadUser(t, db, resp.User.Id)
		if created.ReferredByUserID == nil || *created.ReferredByUserID != referrer.ID {
			t.Fatalf("referred_by_user_id = %v, want %s", created.ReferredByUserID, referrer.ID)
		}
	})

	t.Run("register với ref invalid hoặc self-ref vẫn tạo user", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)

		resp, err := services.Register(context.Background(), &appv1.RegisterRequest{
			Username:    "selfie",
			Email:       "selfie@example.com",
			Password:    "secret123",
			RefUsername: ptrString("selfie"),
		})
		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}
		created := mustLoadUser(t, db, resp.User.Id)
		if created.ReferredByUserID != nil {
			t.Fatalf("referred_by_user_id = %v, want nil", created.ReferredByUserID)
		}
	})
}

func TestResolveSignupReferrerID(t *testing.T) {
	t.Run("resolve referrer theo username hợp lệ", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		referrer := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "ref@example.com", Username: ptrString("alice"), Role: ptrString("USER")})
		referrerID, err := services.resolveSignupReferrerID(context.Background(), "alice", "bob")
		if err != nil {
			t.Fatalf("resolveSignupReferrerID() error = %v", err)
		}
		if referrerID == nil || *referrerID != referrer.ID {
			t.Fatalf("referrerID = %v, want %s", referrerID, referrer.ID)
		}
	})

	t.Run("invalid hoặc self-ref bị ignore", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		referrerID, err := services.resolveSignupReferrerID(context.Background(), "bob", "bob")
		if err != nil {
			t.Fatalf("resolveSignupReferrerID() error = %v", err)
		}
		if referrerID != nil {
			t.Fatalf("referrerID = %v, want nil", referrerID)
		}
	})

	t.Run("username trùng thì ignore trong signup path", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "a@example.com", Username: ptrString("alice"), Role: ptrString("USER")})
		seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "b@example.com", Username: ptrString("alice"), Role: ptrString("USER")})
		referrerID, err := services.resolveSignupReferrerID(context.Background(), "alice", "bob")
		if err != nil {
			t.Fatalf("resolveSignupReferrerID() error = %v", err)
		}
		if referrerID != nil {
			t.Fatalf("referrerID = %v, want nil", referrerID)
		}
	})
}

func TestReferralRewardFlow(t *testing.T) {
	setup := func(t *testing.T) (*appServices, *gorm.DB, model.User, model.User, model.Plan) {
		t.Helper()
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		referrer := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "ref@example.com", Username: ptrString("alice"), Role: ptrString("USER"), ReferralEligible: ptrBool(true)})
		referee := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "payer@example.com", Username: ptrString("bob"), Role: ptrString("USER"), ReferredByUserID: &referrer.ID, ReferralEligible: ptrBool(true)})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 20, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: ptrBool(true)})
		return services, db, referrer, referee, plan
	}

	t.Run("first subscription thưởng 5 phần trăm", func(t *testing.T) {
		services, db, referrer, referee, plan := setup(t)
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: referee.ID, Type: walletTransactionTypeTopup, Amount: 20, Currency: ptrString("USD")})

		result, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet})
		if err != nil {
			t.Fatalf("executePaymentFlow() error = %v", err)
		}
		updatedReferee := mustLoadUser(t, db, referee.ID)
		if updatedReferee.ReferralRewardPaymentID == nil || *updatedReferee.ReferralRewardPaymentID != result.Payment.ID {
			t.Fatalf("reward payment id = %v, want %s", updatedReferee.ReferralRewardPaymentID, result.Payment.ID)
		}
		if updatedReferee.ReferralRewardAmount == nil || *updatedReferee.ReferralRewardAmount != 1 {
			t.Fatalf("reward amount = %v, want 1", updatedReferee.ReferralRewardAmount)
		}
		balance, err := model.GetWalletBalance(context.Background(), db, referrer.ID)
		if err != nil {
			t.Fatalf("GetWalletBalance() error = %v", err)
		}
		if balance != 1 {
			t.Fatalf("referrer wallet balance = %v, want 1", balance)
		}
		notifications := mustListNotificationsByUser(t, db, referrer.ID)
		if len(notifications) != 1 || notifications[0].Type != "billing.referral_reward" {
			t.Fatalf("notifications = %#v, want one referral reward notification", notifications)
		}
	})

	t.Run("subscription thứ hai không thưởng lại", func(t *testing.T) {
		services, db, referrer, referee, plan := setup(t)
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: referee.ID, Type: walletTransactionTypeTopup, Amount: 40, Currency: ptrString("USD")})
		if _, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet}); err != nil {
			t.Fatalf("first executePaymentFlow() error = %v", err)
		}
		if _, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet}); err != nil {
			t.Fatalf("second executePaymentFlow() error = %v", err)
		}
		balance, err := model.GetWalletBalance(context.Background(), db, referrer.ID)
		if err != nil {
			t.Fatalf("GetWalletBalance() error = %v", err)
		}
		if balance != 1 {
			t.Fatalf("referrer wallet balance = %v, want 1", balance)
		}
	})

	t.Run("topup ví đơn thuần không kích hoạt reward", func(t *testing.T) {
		services, db, referrer, referee, _ := setup(t)
		_, err := services.TopupWallet(testActorIncomingContext(referee.ID, "USER"), &appv1.TopupWalletRequest{Amount: 10})
		if err != nil {
			t.Fatalf("TopupWallet() error = %v", err)
		}
		balance, err := model.GetWalletBalance(context.Background(), db, referrer.ID)
		if err != nil {
			t.Fatalf("GetWalletBalance() error = %v", err)
		}
		if balance != 0 {
			t.Fatalf("referrer wallet balance = %v, want 0", balance)
		}
	})

	t.Run("referrer không eligible thì không grant", func(t *testing.T) {
		services, db, referrer, referee, plan := setup(t)
		if err := db.Model(&model.User{}).Where("id = ?", referrer.ID).Update("referral_eligible", false).Error; err != nil {
			t.Fatalf("update referral_eligible: %v", err)
		}
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: referee.ID, Type: walletTransactionTypeTopup, Amount: 20, Currency: ptrString("USD")})
		if _, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet}); err != nil {
			t.Fatalf("executePaymentFlow() error = %v", err)
		}
		balance, err := model.GetWalletBalance(context.Background(), db, referrer.ID)
		if err != nil {
			t.Fatalf("GetWalletBalance() error = %v", err)
		}
		if balance != 0 {
			t.Fatalf("referrer wallet balance = %v, want 0", balance)
		}
	})

	t.Run("override reward bps áp dụng đúng", func(t *testing.T) {
		services, db, referrer, referee, plan := setup(t)
		if err := db.Model(&model.User{}).Where("id = ?", referrer.ID).Update("referral_reward_bps", 750).Error; err != nil {
			t.Fatalf("update referral_reward_bps: %v", err)
		}
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: referee.ID, Type: walletTransactionTypeTopup, Amount: 20, Currency: ptrString("USD")})
		if _, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet}); err != nil {
			t.Fatalf("executePaymentFlow() error = %v", err)
		}
		balance, err := model.GetWalletBalance(context.Background(), db, referrer.ID)
		if err != nil {
			t.Fatalf("GetWalletBalance() error = %v", err)
		}
		if balance != 1.5 {
			t.Fatalf("referrer wallet balance = %v, want 1.5", balance)
		}
	})
}

func TestUpdateAdminUserReferralSettings(t *testing.T) {
	db := newTestDB(t)
	services := newTestAppServices(t, db)
	admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})
	referrer := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "ref@example.com", Username: ptrString("alice"), Role: ptrString("USER")})
	referee := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "payer@example.com", Username: ptrString("bob"), Role: ptrString("USER"), ReferredByUserID: &referrer.ID, ReferralEligible: ptrBool(true)})
	plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 20, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: ptrBool(true)})
	seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: referee.ID, Type: walletTransactionTypeTopup, Amount: 20, Currency: ptrString("USD")})
	if _, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{UserID: referee.ID, Plan: &plan, TermMonths: 1, PaymentMethod: paymentMethodWallet}); err != nil {
		t.Fatalf("executePaymentFlow() error = %v", err)
	}

	_, err := services.UpdateAdminUserReferralSettings(testActorIncomingContext(admin.ID, "ADMIN"), &appv1.UpdateAdminUserReferralSettingsRequest{
		Id:          referee.ID,
		RefUsername: ptrString("alice"),
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		if part != "" && strings.Contains(value, part) {
			return true
		}
	}
	return false
}
