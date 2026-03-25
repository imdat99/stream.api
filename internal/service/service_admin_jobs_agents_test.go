package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/video"
	runtimeservices "stream.api/internal/video/runtime/services"
)

func TestListAdminJobsCursorPagination(t *testing.T) {
	db := newTestDB(t)
	ensureTestJobsTable(t, db)

	services := newTestAppServices(t, db)
	services.videoService = video.NewService(db, runtimeservices.NewJobService(nil, nil))
	admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})

	baseTime := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)
	seedTestJob(t, db, model.Job{ID: "job-300", CreatedAt: ptrTime(baseTime.Add(time.Minute)), UpdatedAt: ptrTime(baseTime.Add(time.Minute))})
	seedTestJob(t, db, model.Job{ID: "job-200", CreatedAt: ptrTime(baseTime), UpdatedAt: ptrTime(baseTime)})
	seedTestJob(t, db, model.Job{ID: "job-100", CreatedAt: ptrTime(baseTime), UpdatedAt: ptrTime(baseTime)})

	conn, cleanup := newTestGRPCServer(t, services)
	defer cleanup()

	client := newAdminClient(conn)
	resp, err := client.ListAdminJobs(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminJobsRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListAdminJobs(first page) error = %v", err)
	}
	assertAdminJobIDs(t, resp.GetJobs(), []string{"job-300", "job-200"})
	if !resp.GetHasMore() {
		t.Fatal("ListAdminJobs(first page) has_more = false, want true")
	}
	if resp.GetNextCursor() == "" {
		t.Fatal("ListAdminJobs(first page) next_cursor is empty")
	}
	if resp.GetPageSize() != 2 {
		t.Fatalf("ListAdminJobs(first page) page_size = %d, want 2", resp.GetPageSize())
	}

	nextCursor := resp.GetNextCursor()
	resp, err = client.ListAdminJobs(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminJobsRequest{
		Cursor:   ptrString(nextCursor),
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("ListAdminJobs(second page) error = %v", err)
	}
	assertAdminJobIDs(t, resp.GetJobs(), []string{"job-100"})
	if resp.GetHasMore() {
		t.Fatal("ListAdminJobs(second page) has_more = true, want false")
	}
	if resp.GetNextCursor() != "" {
		t.Fatalf("ListAdminJobs(second page) next_cursor = %q, want empty", resp.GetNextCursor())
	}
}

func TestListAdminJobsInvalidCursor(t *testing.T) {
	db := newTestDB(t)
	ensureTestJobsTable(t, db)

	services := newTestAppServices(t, db)
	services.videoService = video.NewService(db, runtimeservices.NewJobService(nil, nil))
	admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})

	conn, cleanup := newTestGRPCServer(t, services)
	defer cleanup()

	client := newAdminClient(conn)
	_, err := client.ListAdminJobs(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminJobsRequest{
		Cursor:   ptrString("not-a-valid-cursor"),
		PageSize: 1,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestListAdminJobsCursorRejectsAgentMismatch(t *testing.T) {
	db := newTestDB(t)
	ensureTestJobsTable(t, db)

	services := newTestAppServices(t, db)
	services.videoService = video.NewService(db, runtimeservices.NewJobService(nil, nil))
	admin := seedTestUser(t, db, model.User{ID: uuid.NewString(), Email: "admin@example.com", Role: ptrString("ADMIN")})

	baseTime := time.Date(2026, 3, 22, 11, 0, 0, 0, time.UTC)
	agentOne := int64(101)
	agentTwo := int64(202)
	seedTestJob(t, db, model.Job{ID: "job-b", AgentID: &agentOne, CreatedAt: ptrTime(baseTime.Add(time.Minute)), UpdatedAt: ptrTime(baseTime.Add(time.Minute))})
	seedTestJob(t, db, model.Job{ID: "job-a", AgentID: &agentOne, CreatedAt: ptrTime(baseTime), UpdatedAt: ptrTime(baseTime)})
	seedTestJob(t, db, model.Job{ID: "job-x", AgentID: &agentTwo, CreatedAt: ptrTime(baseTime.Add(2 * time.Minute)), UpdatedAt: ptrTime(baseTime.Add(2 * time.Minute))})

	conn, cleanup := newTestGRPCServer(t, services)
	defer cleanup()

	client := newAdminClient(conn)
	resp, err := client.ListAdminJobs(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminJobsRequest{
		AgentId:  ptrString("101"),
		PageSize: 1,
	})
	if err != nil {
		t.Fatalf("ListAdminJobs(filtered first page) error = %v", err)
	}
	if resp.GetNextCursor() == "" {
		t.Fatal("ListAdminJobs(filtered first page) next_cursor is empty")
	}

	_, err = client.ListAdminJobs(testActorOutgoingContext(admin.ID, "ADMIN"), &appv1.ListAdminJobsRequest{
		AgentId:  ptrString("202"),
		Cursor:   ptrString(resp.GetNextCursor()),
		PageSize: 1,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func ensureTestJobsTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	stmt := `CREATE TABLE jobs (
		id TEXT PRIMARY KEY,
		status TEXT,
		priority INTEGER,
		input_url TEXT,
		output_url TEXT,
		total_duration INTEGER,
		current_time INTEGER,
		progress REAL,
		agent_id INTEGER,
		logs TEXT,
		config TEXT,
		cancelled BOOLEAN NOT NULL DEFAULT 0,
		retry_count INTEGER NOT NULL DEFAULT 0,
		max_retries INTEGER NOT NULL DEFAULT 3,
		created_at DATETIME NOT NULL,
		updated_at DATETIME,
		version INTEGER NOT NULL DEFAULT 1
	)`
	if err := db.Exec(stmt).Error; err != nil {
		t.Fatalf("create jobs table: %v", err)
	}
}

func seedTestJob(t *testing.T, db *gorm.DB, job model.Job) model.Job {
	t.Helper()
	if job.Status == nil {
		job.Status = ptrString("pending")
	}
	if job.Priority == nil {
		job.Priority = ptrInt64(0)
	}
	if job.Config == nil {
		job.Config = ptrString(`{"name":"` + job.ID + `"}`)
	}
	if job.Cancelled == nil {
		job.Cancelled = ptrBool(false)
	}
	if job.RetryCount == nil {
		job.RetryCount = ptrInt64(0)
	}
	if job.MaxRetries == nil {
		job.MaxRetries = ptrInt64(3)
	}
	if job.CreatedAt == nil {
		job.CreatedAt = ptrTime(time.Now().UTC())
	}
	if job.UpdatedAt == nil {
		job.UpdatedAt = ptrTime(job.CreatedAt.UTC())
	}
	if job.Version == nil {
		job.Version = ptrInt64(1)
	}
	if err := db.Create(&job).Error; err != nil {
		t.Fatalf("create job %s: %v", job.ID, err)
	}
	return job
}

func assertAdminJobIDs(t *testing.T, jobs []*appv1.AdminJob, want []string) {
	t.Helper()
	if len(jobs) != len(want) {
		t.Fatalf("job count = %d, want %d", len(jobs), len(want))
	}
	for i, job := range jobs {
		if job.GetId() != want[i] {
			t.Fatalf("job[%d].id = %q, want %q", i, job.GetId(), want[i])
		}
	}
}

func ptrTime(v time.Time) *time.Time { return &v }
