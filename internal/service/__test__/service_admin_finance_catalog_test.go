package service

import (
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func TestCreateAdminPayment(t *testing.T) {

	t.Run("happy path admin", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Team", Price: 30, Cycle: "monthly", StorageLimit: 200, UploadLimit: 20, QualityLimit: "1440p", IsActive: ptrBool(true)})
		seedWalletTransaction(t, db, model.WalletTransaction{ID: uuid.NewString(), UserID: user.ID, Type: walletTransactionTypeTopup, Amount: 5, Currency: ptrString("USD")})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newAdminClient(conn)
		resp, err := client.CreateAdminPayment(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.CreateAdminPaymentRequest{
			UserId:        user.ID,
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: paymentMethodTopup,
			TopupAmount:   ptrFloat64(25),
		})
		if err != nil {
			t.Fatalf("CreateAdminPayment() error = %v", err)
		}
		if resp.Payment == nil || resp.Subscription == nil {
			t.Fatalf("CreateAdminPayment() response incomplete: %#v", resp)
		}
		if resp.Payment.UserId != user.ID {
			t.Fatalf("payment user_id = %q, want %q", resp.Payment.UserId, user.ID)
		}
		if resp.InvoiceId != buildInvoiceID(resp.Payment.Id) {
			t.Fatalf("invoice id = %q, want %q", resp.InvoiceId, buildInvoiceID(resp.Payment.Id))
		}
		if resp.Payment.GetWalletAmount() != 30 {
			t.Fatalf("payment wallet_amount = %v, want 30", resp.Payment.GetWalletAmount())
		}
		if resp.Payment.GetTopupAmount() != 25 {
			t.Fatalf("payment topup_amount = %v, want 25", resp.Payment.GetTopupAmount())
		}
	})

	t.Run("wallet thiếu tiền giữ trailer", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		plan := seedTestPlan(t, db, model.Plan{ID: uuid.NewString(), Name: "Team", Price: 30, Cycle: "monthly", StorageLimit: 200, UploadLimit: 20, QualityLimit: "1440p", IsActive: ptrBool(true)})

		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newAdminClient(conn)
		var trailer metadata.MD
		_, err := client.CreateAdminPayment(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.CreateAdminPaymentRequest{
			UserId:        user.ID,
			PlanId:        plan.ID,
			TermMonths:    1,
			PaymentMethod: paymentMethodWallet,
		}, grpc.Trailer(&trailer))
		assertGRPCCode(t, err, codes.InvalidArgument)
		if body := firstTestMetadataValue(trailer, "x-error-body"); body == "" {
			t.Fatal("expected x-error-body trailer")
		}
	})
}
