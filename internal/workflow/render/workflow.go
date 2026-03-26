package render

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/dto"
	"stream.api/internal/repository"
)

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrAdTemplateNotFound    = errors.New("ad template not found")
	ErrJobServiceUnavailable = errors.New("job service is unavailable")
)

type JobService interface {
	ListJobs(ctx context.Context, offset, limit int) (*dto.PaginatedJobs, error)
	ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*dto.PaginatedJobs, error)
	ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*dto.PaginatedJobs, error)
	GetJob(ctx context.Context, id string) (*model.Job, error)
	CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*model.Job, error)
	CancelJob(ctx context.Context, id string) error
	RetryJob(ctx context.Context, id string) (*model.Job, error)
}

type Workflow struct {
	db                 *gorm.DB
	jobService         JobService
	userRepository     userRepository
	workflowRepository videoWorkflowRepository
}

type userRepository interface {
	GetByID(ctx context.Context, userID string) (*model.User, error)
}

type videoWorkflowRepository interface {
	GetUserByID(ctx context.Context, userID string) (*model.User, error)
	CreateVideoWithStorageAndAd(ctx context.Context, video *model.Video, userID string, adTemplateID *string) error
	MarkVideoJobFailed(ctx context.Context, videoID string) error
}

type CreateVideoInput struct {
	UserID       string
	Title        string
	Description  *string
	URL          string
	Size         int64
	Duration     int32
	Format       string
	AdTemplateID *string
}

type CreateVideoResult struct {
	Video *model.Video
	Job   model.Job
}

func New(db *gorm.DB, jobService JobService) *Workflow {
	return &Workflow{
		db:                 db,
		jobService:         jobService,
		userRepository:     repository.NewUserRepository(db),
		workflowRepository: repository.NewVideoWorkflowRepository(db),
	}
}

func (w *Workflow) CreateVideo(ctx context.Context, input CreateVideoInput) (*CreateVideoResult, error) {
	if w == nil || w.db == nil {
		return nil, gorm.ErrInvalidDB
	}

	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return nil, ErrUserNotFound
	}

	user, err := w.workflowRepository.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	title := strings.TrimSpace(input.Title)
	videoURL := strings.TrimSpace(input.URL)
	format := strings.TrimSpace(input.Format)
	statusValue := "processing"
	processingStatus := "PENDING"
	storageType := detectStorageType(videoURL)

	video := &model.Video{
		ID:               uuid.NewString(),
		UserID:           user.ID,
		Name:             title,
		Title:            title,
		Description:      nullableTrimmedString(input.Description),
		URL:              videoURL,
		Size:             input.Size,
		Duration:         input.Duration,
		Format:           format,
		Status:           model.StringPtr(statusValue),
		ProcessingStatus: model.StringPtr(processingStatus),
		StorageType:      model.StringPtr(storageType),
	}
	if err := w.workflowRepository.CreateVideoWithStorageAndAd(ctx, video, user.ID, input.AdTemplateID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAdTemplateNotFound
		}
		return nil, err
	}

	if w.jobService == nil {
		_ = w.workflowRepository.MarkVideoJobFailed(ctx, video.ID)
		return nil, ErrJobServiceUnavailable
	}

	jobPayload, err := buildJobPayload(video.ID, user.ID, videoURL, format)
	if err != nil {
		_ = w.workflowRepository.MarkVideoJobFailed(ctx, video.ID)
		return nil, err
	}

	job, err := w.jobService.CreateJob(ctx, user.ID, video.ID, title, jobPayload, 0, 0)
	if err != nil {
		_ = w.workflowRepository.MarkVideoJobFailed(ctx, video.ID)
		return nil, err
	}

	return &CreateVideoResult{Video: video, Job: *job}, nil
}

func (w *Workflow) ListJobs(ctx context.Context, offset, limit int) (*dto.PaginatedJobs, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.ListJobs(ctx, offset, limit)
}

func (w *Workflow) ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*dto.PaginatedJobs, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.ListJobsByAgent(ctx, agentID, offset, limit)
}

func (w *Workflow) ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*dto.PaginatedJobs, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.ListJobsByCursor(ctx, agentID, cursor, pageSize)
}

func (w *Workflow) GetJob(ctx context.Context, id string) (*model.Job, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.GetJob(ctx, id)
}

func (w *Workflow) CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*model.Job, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.CreateJob(ctx, userID, videoID, name, config, priority, timeLimit)
}

func (w *Workflow) CancelJob(ctx context.Context, id string) error {
	if w == nil || w.jobService == nil {
		return ErrJobServiceUnavailable
	}
	return w.jobService.CancelJob(ctx, id)
}

func (w *Workflow) RetryJob(ctx context.Context, id string) (*model.Job, error) {
	if w == nil || w.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return w.jobService.RetryJob(ctx, id)
}

func buildJobPayload(videoID, userID, videoURL, format string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"video_id":   videoID,
		"user_id":    userID,
		"input_url":  videoURL,
		"source_url": videoURL,
		"format":     format,
	})
}

func nullableTrimmedString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func detectStorageType(rawURL string) string {
	if shouldDeleteStoredObject(rawURL) {
		return "S3"
	}
	return "WORKER"
}

func shouldDeleteStoredObject(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return !strings.HasPrefix(trimmed, "/")
	}
	return parsed.Scheme == "" && parsed.Host == "" && !strings.HasPrefix(trimmed, "/")
}
