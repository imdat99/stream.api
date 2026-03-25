package service

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/middleware"
)

func TestPlayerConfigsPolicy(t *testing.T) {
	t.Run("free user creates first config", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "free@example.com", Role: ptrString("USER")})

		resp, err := services.CreatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePlayerConfigRequest{
			Name:      "Free Config",
			IsDefault: ptrBool(true),
		})
		if err != nil {
			t.Fatalf("CreatePlayerConfig() error = %v", err)
		}
		if resp.Config == nil {
			t.Fatal("CreatePlayerConfig() config is nil")
		}
		if !resp.Config.IsDefault {
			t.Fatal("CreatePlayerConfig() config should be default")
		}
		items := mustListPlayerConfigsByUser(t, db, user.ID)
		if len(items) != 1 {
			t.Fatalf("player config count = %d, want 1", len(items))
		}
	})

	t.Run("free user cannot create second config", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "free@example.com", Role: ptrString("USER")})
		seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "Existing", IsActive: ptrBool(true)})

		_, err := services.CreatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePlayerConfigRequest{Name: "Second"})
		assertGRPCCode(t, err, codes.FailedPrecondition)
		if got := status.Convert(err).Message(); got != playerConfigFreePlanLimitMessage {
			t.Fatalf("grpc message = %q, want %q", got, playerConfigFreePlanLimitMessage)
		}
	})

	t.Run("free user can update and delete single config", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "free@example.com", Role: ptrString("USER")})
		config := seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "Original", IsActive: ptrBool(true)})

		updateResp, err := services.UpdatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.UpdatePlayerConfigRequest{
			Id:           config.ID,
			Name:         "Updated",
			Description:  ptrString("note"),
			Autoplay:     true,
			ShowControls: true,
			Pip:          true,
			Airplay:      true,
			Chromecast:   true,
			IsActive:     ptrBool(true),
			IsDefault:    ptrBool(true),
		})
		if err != nil {
			t.Fatalf("UpdatePlayerConfig() error = %v", err)
		}
		if updateResp.Config == nil || updateResp.Config.Name != "Updated" || !updateResp.Config.IsDefault {
			t.Fatalf("UpdatePlayerConfig() unexpected response: %#v", updateResp)
		}

		_, err = services.DeletePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.DeletePlayerConfigRequest{Id: config.ID})
		if err != nil {
			t.Fatalf("DeletePlayerConfig() error = %v", err)
		}
		items := mustListPlayerConfigsByUser(t, db, user.ID)
		if len(items) != 0 {
			t.Fatalf("player config count after delete = %d, want 0", len(items))
		}
	})

	t.Run("free downgrade reconciliation only allows delete", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "free@example.com", Role: ptrString("USER")})
		first := seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "First", IsActive: ptrBool(true), IsDefault: true})
		second := seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "Second", IsActive: ptrBool(true)})

		_, err := services.UpdatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.UpdatePlayerConfigRequest{
			Id:           first.ID,
			Name:         "Blocked",
			ShowControls: true,
			Pip:          true,
			Airplay:      true,
			Chromecast:   true,
			IsActive:     ptrBool(true),
		})
		assertGRPCCode(t, err, codes.FailedPrecondition)
		if got := status.Convert(err).Message(); got != playerConfigFreePlanReconciliationMessage {
			t.Fatalf("grpc message = %q, want %q", got, playerConfigFreePlanReconciliationMessage)
		}

		_, err = services.DeletePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.DeletePlayerConfigRequest{Id: second.ID})
		if err != nil {
			t.Fatalf("DeletePlayerConfig() error = %v", err)
		}
		items := mustListPlayerConfigsByUser(t, db, user.ID)
		if len(items) != 1 {
			t.Fatalf("player config count after reconciliation delete = %d, want 1", len(items))
		}
	})

	t.Run("paid user can create multiple configs", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		planID := uuid.NewString()
		seedTestPlan(t, db, model.Plan{ID: planID, Name: "Pro", Price: 10, Cycle: "monthly", StorageLimit: 10, UploadLimit: 1, DurationLimit: 60, QualityLimit: "1080p", IsActive: ptrBool(true)})
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "paid@example.com", Role: ptrString("USER"), PlanID: &planID})

		for _, name := range []string{"One", "Two"} {
			_, err := services.CreatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePlayerConfigRequest{Name: name})
			if err != nil {
				t.Fatalf("CreatePlayerConfig(%q) error = %v", name, err)
			}
		}

		items := mustListPlayerConfigsByUser(t, db, user.ID)
		if len(items) != 2 {
			t.Fatalf("player config count = %d, want 2", len(items))
		}
	})

	t.Run("set default unsets previous default", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		planID := uuid.NewString()
		seedTestPlan(t, db, model.Plan{ID: planID, Name: "Pro", Price: 10, Cycle: "monthly", StorageLimit: 10, UploadLimit: 1, DurationLimit: 60, QualityLimit: "1080p", IsActive: ptrBool(true)})
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "paid@example.com", Role: ptrString("USER"), PlanID: &planID})
		first := seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "First", IsActive: ptrBool(true), IsDefault: true})
		second := seedTestPlayerConfig(t, db, model.PlayerConfig{ID: uuid.NewString(), UserID: user.ID, Name: "Second", IsActive: ptrBool(true), IsDefault: false})

		_, err := services.UpdatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.UpdatePlayerConfigRequest{
			Id:           second.ID,
			Name:         second.Name,
			ShowControls: true,
			Pip:          true,
			Airplay:      true,
			Chromecast:   true,
			IsActive:     ptrBool(true),
			IsDefault:    ptrBool(true),
		})
		if err != nil {
			t.Fatalf("UpdatePlayerConfig() error = %v", err)
		}

		items := mustListPlayerConfigsByUser(t, db, user.ID)
		defaults := map[string]bool{}
		for _, item := range items {
			defaults[item.ID] = item.IsDefault
		}
		if defaults[first.ID] {
			t.Fatal("first config should no longer be default")
		}
		if !defaults[second.ID] {
			t.Fatal("second config should be default")
		}
	})

	t.Run("concurrent free create creates at most one record", func(t *testing.T) {
		db := newTestDB(t)
		services := newTestAppServices(t, db)
		user := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "free@example.com", Role: ptrString("USER")})

		const attempts = 8
		var wg sync.WaitGroup
		var mu sync.Mutex
		successes := 0
		messages := make([]string, 0, attempts)

		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_, err := services.CreatePlayerConfig(testActorIncomingContext(user.ID, "USER"), &appv1.CreatePlayerConfigRequest{Name: "Config-" + uuid.NewString()})
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					successes++
					return
				}
				messages = append(messages, status.Convert(err).Message())
			}(i)
		}
		wg.Wait()

		if successes != 1 {
			t.Fatalf("success count = %d, want 1 (messages=%v)", successes, messages)
		}
		items := mustListPlayerConfigsByUser(t, db, user.ID)
		if len(items) != 1 {
			t.Fatalf("player config count = %d, want 1", len(items))
		}
		for _, message := range messages {
			if message != playerConfigFreePlanLimitMessage && !strings.Contains(strings.ToLower(message), "locked") {
				t.Fatalf("unexpected concurrent create error message: %q", message)
			}
		}
	})
}

func testActorIncomingContext(userID, role string) context.Context {
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.ActorMarkerMetadataKey, testTrustedMarker,
		middleware.ActorIDMetadataKey, userID,
		middleware.ActorRoleMetadataKey, role,
		middleware.ActorEmailMetadataKey, strings.ToLower(role)+"@example.com",
	))
	return context.WithValue(incoming, struct{}{}, time.Now())
}

func seedTestPlayerConfig(t *testing.T, db *gorm.DB, config model.PlayerConfig) model.PlayerConfig {
	t.Helper()
	if config.ShowControls == nil {
		config.ShowControls = ptrBool(true)
	}
	if config.Pip == nil {
		config.Pip = ptrBool(true)
	}
	if config.Airplay == nil {
		config.Airplay = ptrBool(true)
	}
	if config.Chromecast == nil {
		config.Chromecast = ptrBool(true)
	}
	if config.IsActive == nil {
		config.IsActive = ptrBool(true)
	}
	if config.CreatedAt == nil {
		now := time.Now().UTC()
		config.CreatedAt = &now
	}
	if err := db.Create(&config).Error; err != nil {
		t.Fatalf("create player config: %v", err)
	}
	return config
}

func mustListPlayerConfigsByUser(t *testing.T, db *gorm.DB, userID string) []model.PlayerConfig {
	t.Helper()
	var items []model.PlayerConfig
	if err := db.Order("created_at ASC, id ASC").Find(&items, "user_id = ?", userID).Error; err != nil {
		t.Fatalf("list player configs for user %s: %v", userID, err)
	}
	return items
}
