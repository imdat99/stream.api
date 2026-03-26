package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/dto"
)

type AgentRuntime interface {
	ListAgentsWithStats() []*dto.AgentWithStats
	SendCommand(agentID string, cmd string) bool
}

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrAdTemplateNotFound    = errors.New("ad template not found")
	ErrJobServiceUnavailable = errors.New("job service is unavailable")
)

type Service struct {
	db         *gorm.DB
	jobService *JobService
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

func NewService(db *gorm.DB, jobService *JobService) *Service {
	return &Service{db: db, jobService: jobService}
}

func (s *Service) JobService() *JobService {
	if s == nil {
		return nil
	}
	return s.jobService
}

func (s *Service) CreateVideo(ctx context.Context, input CreateVideoInput) (*CreateVideoResult, error) {
	if s == nil || s.db == nil {
		return nil, gorm.ErrInvalidDB
	}

	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return nil, ErrUserNotFound
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
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
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(video).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
			return err
		}
		return saveVideoAdConfig(ctx, tx, video, user.ID, input.AdTemplateID)
	}); err != nil {
		return nil, err
	}

	if s.jobService == nil {
		_ = markVideoJobFailed(ctx, s.db, video.ID)
		return nil, ErrJobServiceUnavailable
	}

	jobPayload, err := buildJobPayload(video.ID, user.ID, videoURL, format)
	if err != nil {
		_ = markVideoJobFailed(ctx, s.db, video.ID)
		return nil, err
	}

	job, err := s.jobService.CreateJob(ctx, user.ID, video.ID, title, jobPayload, 0, 0)
	if err != nil {
		_ = markVideoJobFailed(ctx, s.db, video.ID)
		return nil, err
	}

	return &CreateVideoResult{Video: video, Job: *job}, nil
}

func (s *Service) ListJobs(ctx context.Context, offset, limit int) (*dto.PaginatedJobs, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.ListJobs(ctx, offset, limit)
}

func (s *Service) ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*dto.PaginatedJobs, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.ListJobsByAgent(ctx, agentID, offset, limit)
}

func (s *Service) ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*dto.PaginatedJobs, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.ListJobsByCursor(ctx, agentID, cursor, pageSize)
}

func (s *Service) GetJob(ctx context.Context, id string) (*model.Job, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.GetJob(ctx, id)
}

func (s *Service) CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*model.Job, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.CreateJob(ctx, userID, videoID, name, config, priority, timeLimit)
}

func (s *Service) CancelJob(ctx context.Context, id string) error {
	if s == nil || s.jobService == nil {
		return ErrJobServiceUnavailable
	}
	return s.jobService.CancelJob(ctx, id)
}

func (s *Service) RetryJob(ctx context.Context, id string) (*model.Job, error) {
	if s == nil || s.jobService == nil {
		return nil, ErrJobServiceUnavailable
	}
	return s.jobService.RetryJob(ctx, id)
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

func saveVideoAdConfig(ctx context.Context, tx *gorm.DB, video *model.Video, userID string, adTemplateID *string) error {
	if video == nil || adTemplateID == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*adTemplateID)
	if trimmed == "" {
		if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", nil).Error; err != nil {
			return err
		}
		video.AdID = nil
		return nil
	}

	var template model.AdTemplate
	if err := tx.WithContext(ctx).Select("id").Where("id = ? AND user_id = ?", trimmed, userID).First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdTemplateNotFound
		}
		return err
	}

	if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", template.ID).Error; err != nil {
		return err
	}
	video.AdID = &template.ID
	return nil
}

func markVideoJobFailed(ctx context.Context, db *gorm.DB, videoID string) error {
	if db == nil {
		return nil
	}
	return db.WithContext(ctx).
		Model(&model.Video{}).
		Where("id = ?", strings.TrimSpace(videoID)).
		Updates(map[string]any{"status": "failed", "processing_status": "FAILED"}).Error
}
