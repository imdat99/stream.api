package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/internal/video/runtime/domain"
)

type JobQueue interface {
	Enqueue(ctx context.Context, job *model.Job) error
	Dequeue(ctx context.Context) (*model.Job, error)
}

type LogPubSub interface {
	Publish(ctx context.Context, jobID string, logLine string, progress float64) error
	PublishResource(ctx context.Context, agentID string, data []byte) error
	PublishCancel(ctx context.Context, agentID string, jobID string) error
	PublishJobUpdate(ctx context.Context, jobID string, status string, videoID string) error
	Subscribe(ctx context.Context, jobID string) (<-chan domain.LogEntry, error)
	SubscribeResources(ctx context.Context) (<-chan domain.SystemResource, error)
	SubscribeCancel(ctx context.Context, agentID string) (<-chan string, error)
	SubscribeJobUpdates(ctx context.Context) (<-chan string, error)
}

type JobService struct {
	queue  JobQueue
	pubsub LogPubSub
}

func NewJobService(queue JobQueue, pubsub LogPubSub) *JobService {
	return &JobService{queue: queue, pubsub: pubsub}
}

var ErrInvalidJobCursor = errors.New("invalid job cursor")

const (
	defaultJobPageSize = 20
	maxJobPageSize     = 100
	jobCursorVersion   = 1
)

type PaginatedJobs struct {
	Jobs       []*model.Job `json:"jobs"`
	Total      int64        `json:"total"`
	Offset     int          `json:"offset"`
	Limit      int          `json:"limit"`
	HasMore    bool         `json:"has_more"`
	NextCursor string       `json:"next_cursor,omitempty"`
	PageSize   int          `json:"page_size"`
}

type jobListCursor struct {
	Version           int    `json:"v"`
	CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
	ID                string `json:"id"`
	AgentID           string `json:"agent_id,omitempty"`
}

type jobConfigEnvelope struct {
	Image       string            `json:"image,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Name        string            `json:"name,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	VideoID     string            `json:"video_id,omitempty"`
	TimeLimit   int64             `json:"time_limit,omitempty"`
}

func strPtr(v string) *string        { return &v }
func int64Ptr(v int64) *int64        { return &v }
func boolPtr(v bool) *bool           { return &v }
func float64Ptr(v float64) *float64  { return &v }
func timePtr(v time.Time) *time.Time { return &v }

func parseJobConfig(raw *string) jobConfigEnvelope {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return jobConfigEnvelope{}
	}
	var cfg jobConfigEnvelope
	_ = json.Unmarshal([]byte(*raw), &cfg)
	return cfg
}

func encodeJobConfig(raw []byte, name, userID, videoID string, timeLimit int64) string {
	cfg := parseJobConfig(strPtr(string(raw)))
	if name != "" {
		cfg.Name = name
	}
	if userID != "" {
		cfg.UserID = userID
	}
	if videoID != "" {
		cfg.VideoID = videoID
	}
	if timeLimit > 0 {
		cfg.TimeLimit = timeLimit
	}
	encoded, _ := json.Marshal(cfg)
	return string(encoded)
}

func normalizeJobPageSize(pageSize int) int {
	if pageSize <= 0 {
		return defaultJobPageSize
	}
	if pageSize > maxJobPageSize {
		return maxJobPageSize
	}
	return pageSize
}

func encodeJobListCursor(cursor jobListCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeJobListCursor(raw string) (*jobListCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrInvalidJobCursor
	}
	var cursor jobListCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return nil, ErrInvalidJobCursor
	}
	if cursor.Version != jobCursorVersion || cursor.CreatedAtUnixNano <= 0 || strings.TrimSpace(cursor.ID) == "" {
		return nil, ErrInvalidJobCursor
	}
	cursor.ID = strings.TrimSpace(cursor.ID)
	cursor.AgentID = strings.TrimSpace(cursor.AgentID)
	return &cursor, nil
}

func buildJobListCursor(job *model.Job, agentID string) (string, error) {
	if job == nil || job.CreatedAt == nil {
		return "", nil
	}
	return encodeJobListCursor(jobListCursor{
		Version:           jobCursorVersion,
		CreatedAtUnixNano: job.CreatedAt.UTC().UnixNano(),
		ID:                strings.TrimSpace(job.ID),
		AgentID:           strings.TrimSpace(agentID),
	})
}

func listJobsByOffset(ctx context.Context, agentID string, offset, limit int) (*PaginatedJobs, error) {
	if offset < 0 {
		offset = 0
	}
	limit = normalizeJobPageSize(limit)
	q := query.Job.WithContext(ctx).Order(query.Job.CreatedAt.Desc(), query.Job.ID.Desc())
	if agentID != "" {
		agentNumeric, err := strconv.ParseInt(agentID, 10, 64)
		if err != nil {
			return &PaginatedJobs{Jobs: []*model.Job{}, Total: 0, Offset: offset, Limit: limit, PageSize: limit, HasMore: false}, nil
		}
		q = q.Where(query.Job.AgentID.Eq(agentNumeric))
	}
	jobs, total, err := q.FindByPage(offset, limit)
	if err != nil {
		return nil, err
	}
	items := make([]*model.Job, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, job)
	}
	return &PaginatedJobs{Jobs: items, Total: total, Offset: offset, Limit: limit, PageSize: limit, HasMore: offset+len(items) < int(total)}, nil
}

func (s *JobService) CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*model.Job, error) {
	status := string(domain.JobStatusPending)
	now := time.Now()
	job := &model.Job{
		ID:         fmt.Sprintf("job-%d", now.UnixNano()),
		Status:     strPtr(status),
		Priority:   int64Ptr(int64(priority)),
		Config:     strPtr(encodeJobConfig(config, name, userID, videoID, timeLimit)),
		Cancelled:  boolPtr(false),
		RetryCount: int64Ptr(0),
		MaxRetries: int64Ptr(3),
		CreatedAt:  timePtr(now),
		UpdatedAt:  timePtr(now),
	}
	if err := query.Job.WithContext(ctx).Create(job); err != nil {
		return nil, err
	}
	if err := syncVideoStatus(ctx, videoID, domain.JobStatusPending); err != nil {
		return nil, err
	}
	// domainJob := toDomainJob(job)
	if err := s.queue.Enqueue(ctx, job); err != nil {
		return nil, err
	}
	_ = s.pubsub.PublishJobUpdate(ctx, job.ID, status, videoID)
	return job, nil
}

func (s *JobService) ListJobs(ctx context.Context, offset, limit int) (*PaginatedJobs, error) {
	return listJobsByOffset(ctx, "", offset, limit)
}

func (s *JobService) ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*PaginatedJobs, error) {
	return listJobsByOffset(ctx, strings.TrimSpace(agentID), offset, limit)
}

func (s *JobService) ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*PaginatedJobs, error) {
	agentID = strings.TrimSpace(agentID)
	pageSize = normalizeJobPageSize(pageSize)

	decodedCursor, err := decodeJobListCursor(cursor)
	if err != nil {
		return nil, err
	}
	if decodedCursor != nil && decodedCursor.AgentID != agentID {
		return nil, ErrInvalidJobCursor
	}

	q := query.Job.WithContext(ctx).Order(query.Job.CreatedAt.Desc(), query.Job.ID.Desc())
	if agentID != "" {
		agentNumeric, err := strconv.ParseInt(agentID, 10, 64)
		if err != nil {
			return &PaginatedJobs{Jobs: []*model.Job{}, Total: 0, Limit: pageSize, PageSize: pageSize, HasMore: false}, nil
		}
		q = q.Where(query.Job.AgentID.Eq(agentNumeric))
	}
	var cursorTime time.Time
	if decodedCursor != nil {
		cursorTime = time.Unix(0, decodedCursor.CreatedAtUnixNano).UTC()
	}

	queryDB := q.UnderlyingDB()
	if decodedCursor != nil {
		queryDB = queryDB.Where("(created_at < ?) OR (created_at = ? AND id < ?)", cursorTime, cursorTime, decodedCursor.ID)
	}

	var jobs []*model.Job
	if err := queryDB.Limit(pageSize + 1).Find(&jobs).Error; err != nil {
		return nil, err
	}

	hasMore := len(jobs) > pageSize
	if hasMore {
		jobs = jobs[:pageSize]
	}

	items := make([]*model.Job, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, job)
	}

	nextCursor := ""
	if hasMore && len(jobs) > 0 {
		nextCursor, err = buildJobListCursor(jobs[len(jobs)-1], agentID)
		if err != nil {
			return nil, err
		}
	}

	return &PaginatedJobs{
		Jobs:       items,
		Total:      0,
		Limit:      pageSize,
		PageSize:   pageSize,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *JobService) GetJob(ctx context.Context, id string) (*model.Job, error) {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(id)).First()
	if err != nil {
		return nil, err
	}
	return job, nil
}

func (s *JobService) GetNextJob(ctx context.Context) (*model.Job, error) {
	return s.queue.Dequeue(ctx)
}
func (s *JobService) SubscribeSystemResources(ctx context.Context) (<-chan domain.SystemResource, error) {
	return s.pubsub.SubscribeResources(ctx)
}
func (s *JobService) SubscribeJobLogs(ctx context.Context, jobID string) (<-chan domain.LogEntry, error) {
	return s.pubsub.Subscribe(ctx, jobID)
}
func (s *JobService) SubscribeCancel(ctx context.Context, agentID string) (<-chan string, error) {
	return s.pubsub.SubscribeCancel(ctx, agentID)
}
func (s *JobService) SubscribeJobUpdates(ctx context.Context) (<-chan string, error) {
	return s.pubsub.SubscribeJobUpdates(ctx)
}

func (s *JobService) UpdateJobStatus(ctx context.Context, jobID string, status domain.JobStatus) error {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return err
	}
	now := time.Now()
	job.Status = strPtr(string(status))
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return err
	}
	cfg := parseJobConfig(job.Config)
	if err := syncVideoStatus(ctx, cfg.VideoID, status); err != nil {
		return err
	}
	return s.pubsub.PublishJobUpdate(ctx, jobID, string(status), cfg.VideoID)
}

func (s *JobService) AssignJob(ctx context.Context, jobID string, agentID string) error {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return err
	}
	agentNumeric, err := strconv.ParseInt(agentID, 10, 64)
	if err != nil {
		return err
	}
	now := time.Now()
	status := string(domain.JobStatusRunning)
	job.AgentID = &agentNumeric
	job.Status = &status
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return err
	}
	cfg := parseJobConfig(job.Config)
	if err := syncVideoStatus(ctx, cfg.VideoID, domain.JobStatusRunning); err != nil {
		return err
	}
	return s.pubsub.PublishJobUpdate(ctx, jobID, status, cfg.VideoID)
}

func (s *JobService) CancelJob(ctx context.Context, jobID string) error {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}
	currentStatus := ""
	if job.Status != nil {
		currentStatus = *job.Status
	}
	if currentStatus != string(domain.JobStatusPending) && currentStatus != string(domain.JobStatusRunning) {
		return fmt.Errorf("cannot cancel job with status %s", currentStatus)
	}
	cancelled := true
	status := string(domain.JobStatusCancelled)
	now := time.Now()
	job.Cancelled = &cancelled
	job.Status = &status
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return err
	}
	cfg := parseJobConfig(job.Config)
	if err := syncVideoStatus(ctx, cfg.VideoID, domain.JobStatusCancelled); err != nil {
		return err
	}
	_ = s.pubsub.PublishJobUpdate(ctx, jobID, status, cfg.VideoID)
	if job.AgentID != nil {
		_ = s.pubsub.PublishCancel(ctx, strconv.FormatInt(*job.AgentID, 10), job.ID)
	}
	return s.pubsub.Publish(ctx, jobID, "[SYSTEM] Job cancelled by admin", -1)
}

func (s *JobService) RetryJob(ctx context.Context, jobID string) (*model.Job, error) {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return nil, fmt.Errorf("job not found: %w", err)
	}
	currentStatus := ""
	if job.Status != nil {
		currentStatus = *job.Status
	}
	if currentStatus != string(domain.JobStatusFailure) && currentStatus != string(domain.JobStatusCancelled) {
		return nil, fmt.Errorf("cannot retry job with status %s", currentStatus)
	}
	currentRetry := int64(0)
	if job.RetryCount != nil {
		currentRetry = *job.RetryCount
	}
	maxRetries := int64(3)
	if job.MaxRetries != nil {
		maxRetries = *job.MaxRetries
	}
	if currentRetry >= maxRetries {
		return nil, fmt.Errorf("max retries (%d) exceeded", maxRetries)
	}
	pending := string(domain.JobStatusPending)
	cancelled := false
	progress := 0.0
	now := time.Now()
	job.Status = &pending
	job.Cancelled = &cancelled
	job.RetryCount = int64Ptr(currentRetry + 1)
	job.Progress = &progress
	job.AgentID = nil
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return nil, err
	}
	cfg := parseJobConfig(job.Config)
	if err := syncVideoStatus(ctx, cfg.VideoID, domain.JobStatusPending); err != nil {
		return nil, err
	}
	// domainJob := toDomainJob(job)
	if err := s.queue.Enqueue(ctx, job); err != nil {
		return nil, err
	}
	_ = s.pubsub.PublishJobUpdate(ctx, jobID, pending, cfg.VideoID)
	return job, nil
}

func (s *JobService) UpdateJobProgress(ctx context.Context, jobID string, progress float64) error {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return err
	}
	now := time.Now()
	job.Progress = float64Ptr(progress)
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return err
	}
	return s.pubsub.Publish(ctx, jobID, "", progress)
}

func (s *JobService) ProcessLog(ctx context.Context, jobID string, logData []byte) error {
	line := string(logData)
	re := regexp.MustCompile(`out_time_us=(\d+)`)
	matches := re.FindStringSubmatch(line)
	var progress float64
	if len(matches) > 1 {
		us, _ := strconv.ParseInt(matches[1], 10, 64)
		if us > 0 {
			progress = float64(us) / 1000000.0
		}
	}
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(jobID)).First()
	if err != nil {
		return err
	}
	existingLogs := ""
	if job.Logs != nil {
		existingLogs = *job.Logs
	}
	newLog := line
	if !strings.HasSuffix(newLog, "\n") {
		newLog += "\n"
	}
	existingLogs += newLog
	if len(existingLogs) > 10*1024*1024 {
		existingLogs = existingLogs[len(existingLogs)-8*1024*1024:]
	}
	now := time.Now()
	job.Logs = &existingLogs
	if progress > 0 {
		job.Progress = float64Ptr(progress)
	}
	job.UpdatedAt = &now
	if err := query.Job.WithContext(ctx).Save(job); err != nil {
		return err
	}
	return s.pubsub.Publish(ctx, jobID, line, progress)
}

func syncVideoStatus(ctx context.Context, videoID string, status domain.JobStatus) error {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" {
		return nil
	}

	statusValue := "processing"
	processingStatus := "PROCESSING"
	switch status {
	case domain.JobStatusSuccess:
		statusValue = "ready"
		processingStatus = "READY"
	case domain.JobStatusFailure, domain.JobStatusCancelled:
		statusValue = "failed"
		processingStatus = "FAILED"
	}

	_, err := query.Video.WithContext(ctx).
		Where(query.Video.ID.Eq(videoID)).
		Updates(map[string]any{"status": statusValue, "processing_status": processingStatus})
	return err
}

func (s *JobService) PublishSystemResources(ctx context.Context, agentID string, data []byte) error {
	return s.pubsub.PublishResource(ctx, agentID, data)
}
