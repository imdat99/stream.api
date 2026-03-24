package app

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/middleware"
)

func TestCreatePayment(t *testing.T) {

	t.Run("plan không tồn tại", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		_, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        uuid.NewString(),
			TermMonths:    1,
			PaymentMethod: paymentMethodWallet,
		})
		assertGRPCCode(t, err, codes.NotFound)
	})

	t.Run("plan inactive", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Starter", Price: 10, Cycle: "monthly", StorageLimit: 10, UploadLimit: 1, QualityLimit: "720p", IsActive: ptrBool(false)})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		_, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: paymentMethodWallet,
		})
		assertGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("term không hợp lệ", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Starter", Price: 10, Cycle: "monthly", StorageLimit: 10, UploadLimit: 1, QualityLimit: "720p", IsActive: ptrBool(true)})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		_, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        plan.ID,
			TermMonths:    2,
			PaymentMethod: paymentMethodWallet,
		})
		assertGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("payment method không hợp lệ", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Starter", Price: 10, Cycle: "monthly", StorageLimit: 10, UploadLimit: 1, QualityLimit: "720p", IsActive: ptrBool(true)})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		_, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: "bank_transfer",
		})
		assertGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("wallet thiếu tiền giữ trailer", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 50, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: ptrBool(true)})
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: walletTransactionTypeTopup, Amount: 10, Currency: ptrString("USD")})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		var trailer metadata.MD
		_, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: paymentMethodWallet,
		}, grpc.Trailer(&trailer))
		assertGRPCCode(t, err, codes.InvalidArgument)
		body := firstTestMetadataValue(trailer, "x-error-body")
		if body == "" {
			t.Fatal("expected x-error-body trailer")
		}
		if !strings.Contains(body, "Insufficient wallet balance") {
			t.Fatalf("x-error-body = %q, want insufficient wallet balance", body)
		}
	})

	t.Run("happy path user", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Pro", Price: 20, Cycle: "monthly", StorageLimit: 100, UploadLimit: 10, QualityLimit: "1080p", IsActive: ptrBool(true)})
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: walletTransactionTypeTopup, Amount: 5, Currency: ptrString("USD")})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newPaymentsClient(conn)
		resp, err := client.CreatePayment(testActorOutgoingContext(user.ID, "USER"), &appv1.CreatePaymentRequest{
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: paymentMethodTopup,
			TopupAmount:   ptrFloat64(15),
		})
		if err != nil {
			t.Fatalf("CreatePayment() error = %v", err)
		}
		if resp.Payment == nil || resp.Subscription == nil {
			t.Fatalf("CreatePayment() response incomplete: %#v", resp)
		}
		if resp.InvoiceId != buildInvoiceID(resp.Payment.Id) {
			t.Fatalf("invoice id = %q, want %q", resp.InvoiceId, buildInvoiceID(resp.Payment.Id))
		}
		if resp.Subscription.PaymentMethod != paymentMethodTopup {
			t.Fatalf("subscription payment method = %q, want %q", resp.Subscription.PaymentMethod, paymentMethodTopup)
		}
		if resp.Subscription.WalletAmount != 20 {
			t.Fatalf("subscription wallet amount = %v, want 20", resp.Subscription.WalletAmount)
		}
		if resp.Subscription.TopupAmount != 15 {
			t.Fatalf("subscription topup amount = %v, want 15", resp.Subscription.TopupAmount)
		}
		if resp.WalletBalance != 0 {
			t.Fatalf("wallet balance = %v, want 0", resp.WalletBalance)
		}

		payment := mustLoadPayment(t, db, resp.Payment.Id)
		if payment.Amount != 20 {
			t.Fatalf("payment amount = %v, want 20", payment.Amount)
		}
	})
}

func testActorOutgoingContext(userID, role string) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		middleware.ActorMarkerMetadataKey, testTrustedMarker,
		middleware.ActorIDMetadataKey, userID,
		middleware.ActorRoleMetadataKey, role,
		middleware.ActorEmailMetadataKey, strings.ToLower(role)+"@example.com",
	))
}

func assertGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("grpc error = nil, want %v", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("grpc code = %v, want %v, err=%v", got, want, err)
	}
}
