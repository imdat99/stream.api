package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

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

func TestExecutePaymentFlow_PublishesNotificationEvent(t *testing.T) {
	db := newTestDB(t)
	services := newTestAppServices(t, db)
	publisher := &fakeNotificationEventPublisher{}
	services.notificationEvents = publisher

	user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "payer@example.com", Role: ptrString("USER")})
	plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 10, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: ptrBool(true)})
	seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: walletTransactionTypeTopup, Amount: 5, Currency: ptrString("USD")})

	result, err := services.executePaymentFlow(context.Background(), paymentExecutionInput{
		UserID:        user.ID,
		Plan:          &plan,
		TermMonths:    1,
		PaymentMethod: paymentMethodTopup,
		TopupAmount:   ptrFloat64(5),
	})
	if err != nil {
		t.Fatalf("executePaymentFlow() error = %v", err)
	}
	if result == nil {
		t.Fatal("executePaymentFlow() result is nil")
	}
	if len(publisher.events) != 1 {
		t.Fatalf("published events = %d, want 1", len(publisher.events))
	}
	if publisher.events[0].notification == nil || publisher.events[0].notification.Type != "billing.subscription" {
		t.Fatalf("published notification = %#v", publisher.events[0].notification)
	}
}

func TestTopupWallet_PublishesNotificationEvent(t *testing.T) {
	db := newTestDB(t)
	services := newTestAppServices(t, db)
	publisher := &fakeNotificationEventPublisher{}
	services.notificationEvents = publisher
	user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})

	_, err := (&paymentsAppService{appServices: services}).TopupWallet(testActorIncomingContext(user.ID, "USER"), &appv1.TopupWalletRequest{Amount: 12})
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
	notification := &model.Notification{
		ID:          uuid.NewString(),
		UserID:      uuid.NewString(),
		Type:        "billing.subscription",
		Title:       "Subscription activated",
		Message:     "Your subscription is active.",
		ActionURL:   ptrString("/settings/billing"),
		ActionLabel: ptrString("Renew plan"),
		CreatedAt:   &now,
	}
	payload := BuildNotificationCreatedPayload(notification)
	if payload.ID != notification.ID || payload.UserID != notification.UserID || payload.Type != notification.Type {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.CreatedAt == "" {
		t.Fatal("payload created_at should not be empty")
	}
}
