package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func TestPopupAdsUserFlow(t *testing.T) {
	t.Run("create list update delete popup ad", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})

		startAt := time.Now().UTC().Add(-time.Hour)
		endAt := time.Now().UTC().Add(2 * time.Hour)
		createResp, err := services.CreatePopupAd(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePopupAdRequest{
			Title:                "Homepage Campaign",
			ImageUrl:             "https://cdn.example.com/banner.jpg",
			TargetUrl:            "https://example.com/landing",
			IsActive:             ptrBool(true),
			StartAt:              timeToProto(&startAt),
			EndAt:                timeToProto(&endAt),
			Priority:             int32Ptr(5),
			CloseCooldownMinutes: int32Ptr(90),
		})
		if err != nil {
			t.Fatalf("CreatePopupAd() error = %v", err)
		}
		if createResp.Item == nil || createResp.Item.Title != "Homepage Campaign" {
			t.Fatalf("CreatePopupAd() unexpected response: %#v", createResp)
		}

		listResp, err := services.ListPopupAds(testActorIncomingContext(user.ID, "USER"), &appv1.ListPopupAdsRequest{})
		if err != nil {
			t.Fatalf("ListPopupAds() error = %v", err)
		}
		if len(listResp.Items) != 1 {
			t.Fatalf("ListPopupAds() count = %d, want 1", len(listResp.Items))
		}

		updateResp, err := services.UpdatePopupAd(testActorIncomingContext(user.ID, "USER"), &appv1.UpdatePopupAdRequest{
			Id:                   createResp.Item.Id,
			Title:                "Homepage Campaign v2",
			ImageUrl:             "https://cdn.example.com/banner-v2.jpg",
			TargetUrl:            "https://example.com/landing-v2",
			IsActive:             ptrBool(false),
			Priority:             int32Ptr(8),
			CloseCooldownMinutes: int32Ptr(30),
		})
		if err != nil {
			t.Fatalf("UpdatePopupAd() error = %v", err)
		}
		if updateResp.Item == nil || updateResp.Item.Title != "Homepage Campaign v2" || updateResp.Item.IsActive {
			t.Fatalf("UpdatePopupAd() unexpected response: %#v", updateResp)
		}

		items := mustListPopupAdsByUser(t, db, user.ID)
		if len(items) != 1 {
			t.Fatalf("popup ad count = %d, want 1", len(items))
		}
		if items[0].Priority != 8 || items[0].CloseCooldownMinutes != 30 {
			t.Fatalf("popup ad values = %#v", items[0])
		}

		_, err = services.DeletePopupAd(testActorIncomingContext(user.ID, "USER"), &appv1.DeletePopupAdRequest{Id: createResp.Item.Id})
		if err != nil {
			t.Fatalf("DeletePopupAd() error = %v", err)
		}
		items = mustListPopupAdsByUser(t, db, user.ID)
		if len(items) != 0 {
			t.Fatalf("popup ad count after delete = %d, want 0", len(items))
		}
	})

	t.Run("reject invalid schedule", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		startAt := time.Now().UTC().Add(time.Hour)
		endAt := time.Now().UTC()

		_, err := services.CreatePopupAd(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePopupAdRequest{
			Title:     "Invalid",
			ImageUrl:  "https://cdn.example.com/banner.jpg",
			TargetUrl: "https://example.com/landing",
			StartAt:   timeToProto(&startAt),
			EndAt:     timeToProto(&endAt),
		})
		assertGRPCCode(t, err, codes.InvalidArgument)
	})

	t.Run("get active popup ad picks highest priority valid item", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		now := time.Now().UTC()
		seedTestPopupAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Title: "inactive", ImageURL: "https://cdn.example.com/1.jpg", TargetURL: "https://example.com/1", IsActive: ptrBool(false), Priority: 99})
		seedTestPopupAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Title: "expired", ImageURL: "https://cdn.example.com/2.jpg", TargetURL: "https://example.com/2", IsActive: ptrBool(true), Priority: 50, StartAt: ptrTime(now.Add(-2 * time.Hour)), EndAt: ptrTime(now.Add(-time.Hour))})
		seedTestPopupAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Title: "low", ImageURL: "https://cdn.example.com/3.jpg", TargetURL: "https://example.com/3", IsActive: ptrBool(true), Priority: 1, StartAt: ptrTime(now.Add(-time.Hour)), EndAt: ptrTime(now.Add(time.Hour))})
		winner := seedTestPopupAd(t, db, model.PopupAd{ID: uuid.NewString(), UserID: user.ID, Title: "winner", ImageURL: "https://cdn.example.com/4.jpg", TargetURL: "https://example.com/4", IsActive: ptrBool(true), Priority: 10, StartAt: ptrTime(now.Add(-time.Hour)), EndAt: ptrTime(now.Add(time.Hour)), CloseCooldownMinutes: 15})

		resp, err := services.GetActivePopupAd(testActorIncomingContext(user.ID, "USER"), &appv1.GetActivePopupAdRequest{})
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
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "user@example.com", Role: ptrString("USER")})
		conn, cleanup := newTestGRPCServer(t, services)
		defer cleanup()

		client := newAdminClient(conn)
		createResp, err := client.CreateAdminPopupAd(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.CreateAdminPopupAdRequest{
			UserId:               user.ID,
			Title:                "Admin Campaign",
			ImageUrl:             "https://cdn.example.com/admin.jpg",
			TargetUrl:            "https://example.com/admin",
			IsActive:             ptrBool(true),
			Priority:             int32Ptr(7),
			CloseCooldownMinutes: int32Ptr(45),
		})
		if err != nil {
			t.Fatalf("CreateAdminPopupAd() error = %v", err)
		}
		if createResp.Item == nil || createResp.Item.UserId != user.ID {
			t.Fatalf("CreateAdminPopupAd() unexpected response: %#v", createResp)
		}

		listResp, err := client.ListAdminPopupAds(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminPopupAdsRequest{UserId: &user.ID})
		if err != nil {
			t.Fatalf("ListAdminPopupAds() error = %v", err)
		}
		if len(listResp.Items) != 1 {
			t.Fatalf("ListAdminPopupAds() count = %d, want 1", len(listResp.Items))
		}

		updateResp, err := client.UpdateAdminPopupAd(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.UpdateAdminPopupAdRequest{
			Id:                   createResp.Item.Id,
			UserId:               user.ID,
			Title:                "Admin Campaign v2",
			ImageUrl:             "https://cdn.example.com/admin-v2.jpg",
			TargetUrl:            "https://example.com/admin-v2",
			IsActive:             ptrBool(false),
			Priority:             int32Ptr(11),
			CloseCooldownMinutes: int32Ptr(10),
		})
		if err != nil {
			t.Fatalf("UpdateAdminPopupAd() error = %v", err)
		}
		if updateResp.Item == nil || updateResp.Item.Title != "Admin Campaign v2" || updateResp.Item.IsActive {
			t.Fatalf("UpdateAdminPopupAd() unexpected response: %#v", updateResp)
		}

		_, err = client.DeleteAdminPopupAd(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.DeleteAdminPopupAdRequest{Id: createResp.Item.Id})
		if err != nil {
			t.Fatalf("DeleteAdminPopupAd() error = %v", err)
		}
		items := mustListPopupAdsByUser(t, db, user.ID)
		if len(items) != 0 {
			t.Fatalf("popup ad count after delete = %d, want 0", len(items))
		}
	})
}
