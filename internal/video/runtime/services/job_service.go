package services

import (
	"context"
	"encoding/json"
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
	Enqueue(ctx context.Context, job *domain.Job) error
	Dequeue(ctx context.Context) (*domain.Job, error)
}

type LogPubSub interface {
	Publish(ctx context.Context, jobID string, logLine string, progress float64) error
	PublishResource(ctx context.Context, agentID string, data []byte) error
	PublishCancel(ctx context.Context, agentID string, jobID string) error
	PublishJobUpdate(ctx context.Context, jobID string, status string) error
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

type PaginatedJobs struct {
	Jobs    []*domain.Job `json:"jobs"`
	Total   int64         `json:"total"`
	Offset  int           `json:"offset"`
	Limit   int           `json:"limit"`
	HasMore bool          `json:"has_more"`
}

type jobConfigEnvelope struct {
	Image       string            `json:"image,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Name        string            `json:"name,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	TimeLimit   int64             `json:"time_limit,omitempty"`
}

func strPtr(v string) *string        { return &v }
func int64Ptr(v int64) *int64        { return &v }
func boolPtr(v bool) *bool           { return &v }
func float64Ptr(v float64) *float64  { return &v }
func int32Ptr(v int32) *int32        { return &v }
func timePtr(v time.Time) *time.Time { return &v }

func parseJobConfig(raw *string) jobConfigEnvelope {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return jobConfigEnvelope{}
	}
	var cfg jobConfigEnvelope
	_ = json.Unmarshal([]byte(*raw), &cfg)
	return cfg
}

func encodeJobConfig(raw []byte, name, userID string, timeLimit int64) string {
	cfg := parseJobConfig(strPtr(string(raw)))
	if name != "" {
		cfg.Name = name
	}
	if userID != "" {
		cfg.UserID = userID
	}
	if timeLimit > 0 {
		cfg.TimeLimit = timeLimit
	}
	encoded, _ := json.Marshal(cfg)
	return string(encoded)
}

func toDomainJob(job *model.Job) *domain.Job {
	if job == nil {
		return nil
	}
	cfg := parseJobConfig(job.Config)
	result := &domain.Job{ID: job.ID, Name: cfg.Name, UserID: cfg.UserID, TimeLimit: cfg.TimeLimit}
	if job.Status != nil {
		result.Status = domain.JobStatus(*job.Status)
	}
	if job.Priority != nil {
		result.Priority = int(*job.Priority)
	}
	if job.InputURL != nil {
		result.InputURL = *job.InputURL
	}
	if job.OutputURL != nil {
		result.OutputURL = *job.OutputURL
	}
	if job.TotalDuration != nil {
		result.TotalDuration = *job.TotalDuration
	}
	if job.CurrentTime != nil {
		result.CurrentTime = *job.CurrentTime
	}
	if job.Progress != nil {
		result.Progress = *job.Progress
	}
	if job.AgentID != nil {
		agentID := strconv.FormatInt(*job.AgentID, 10)
		result.AgentID = &agentID
	}
	if job.Logs != nil {
		result.Logs = *job.Logs
	}
	if job.Config != nil {
		result.Config = *job.Config
	}
	if job.Cancelled != nil {
		result.Cancelled = *job.Cancelled
	}
	if job.RetryCount != nil {
		result.RetryCount = int(*job.RetryCount)
	}
	if job.MaxRetries != nil {
		result.MaxRetries = int(*job.MaxRetries)
	}
	if job.CreatedAt != nil {
		result.CreatedAt = *job.CreatedAt
	}
	if job.UpdatedAt != nil {
		result.UpdatedAt = *job.UpdatedAt
	}
	return result
}

func (s *JobService) CreateJob(ctx context.Context, userID string, name string, config []byte, priority int, timeLimit int64) (*domain.Job, error) {
	status := string(domain.JobStatusPending)
	now := time.Now()
	job := &model.Job{
		ID:         fmt.Sprintf("job-%d", now.UnixNano()),
		Status:     strPtr(status),
		Priority:   int64Ptr(int64(priority)),
		Config:     strPtr(encodeJobConfig(config, name, userID, timeLimit)),
		Cancelled:  boolPtr(false),
		RetryCount: int64Ptr(0),
		MaxRetries: int64Ptr(3),
		CreatedAt:  timePtr(now),
		UpdatedAt:  timePtr(now),
	}
	if err := query.Job.WithContext(ctx).Create(job); err != nil {
		return nil, err
	}
	domainJob := toDomainJob(job)
	if err := s.queue.Enqueue(ctx, domainJob); err != nil {
		return nil, err
	}
	return domainJob, nil
}

func (s *JobService) ListJobs(ctx context.Context, offset, limit int) (*PaginatedJobs, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	jobs, total, err := query.Job.WithContext(ctx).Order(query.Job.CreatedAt.Desc()).FindByPage(offset, limit)
	if err != nil {
		return nil, err
	}
	items := make([]*domain.Job, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, toDomainJob(job))
	}
	return &PaginatedJobs{Jobs: items, Total: total, Offset: offset, Limit: limit, HasMore: offset+len(items) < int(total)}, nil
}

func (s *JobService) ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*PaginatedJobs, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	agentNumeric, err := strconv.ParseInt(agentID, 10, 64)
	if err != nil {
		return &PaginatedJobs{Jobs: []*domain.Job{}, Total: 0, Offset: offset, Limit: limit, HasMore: false}, nil
	}
	q := query.Job.WithContext(ctx).Where(query.Job.AgentID.Eq(agentNumeric)).Order(query.Job.CreatedAt.Desc())
	jobs, total, err := q.FindByPage(offset, limit)
	if err != nil {
		return nil, err
	}
	items := make([]*domain.Job, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, toDomainJob(job))
	}
	return &PaginatedJobs{Jobs: items, Total: total, Offset: offset, Limit: limit, HasMore: offset+len(items) < int(total)}, nil
}

func (s *JobService) GetJob(ctx context.Context, id string) (*domain.Job, error) {
	job, err := query.Job.WithContext(ctx).Where(query.Job.ID.Eq(id)).First()
	if err != nil {
		return nil, err
	}
	return toDomainJob(job), nil
}

func (s *JobService) GetNextJob(ctx context.Context) (*domain.Job, error) {
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
	return s.pubsub.PublishJobUpdate(ctx, jobID, string(status))
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
	return s.pubsub.PublishJobUpdate(ctx, jobID, status)
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
	_ = s.pubsub.PublishJobUpdate(ctx, jobID, status)
	if job.AgentID != nil {
		_ = s.pubsub.PublishCancel(ctx, strconv.FormatInt(*job.AgentID, 10), job.ID)
	}
	return s.pubsub.Publish(ctx, jobID, "[SYSTEM] Job cancelled by admin", -1)
}

func (s *JobService) RetryJob(ctx context.Context, jobID string) (*domain.Job, error) {
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
	domainJob := toDomainJob(job)
	if err := s.queue.Enqueue(ctx, domainJob); err != nil {
		return nil, err
	}
	return domainJob, nil
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

func (s *JobService) PublishSystemResources(ctx context.Context, agentID string, data []byte) error {
	return s.pubsub.PublishResource(ctx, agentID, data)
}
