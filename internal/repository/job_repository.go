package repository

import (
	"context"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
)

type jobRepository struct {
	db *gorm.DB
}

func NewJobRepository(db *gorm.DB) *jobRepository {
	return &jobRepository{db: db}
}

func (r *jobRepository) ListByOffset(ctx context.Context, agentID string, offset int, limit int) ([]*model.Job, int64, error) {
	q := query.Job.WithContext(ctx).Order(query.Job.CreatedAt.Desc(), query.Job.ID.Desc())
	if trimmedAgentID := strings.TrimSpace(agentID); trimmedAgentID != "" {
		agentNumeric, err := strconv.ParseInt(trimmedAgentID, 10, 64)
		if err != nil {
			return []*model.Job{}, 0, nil
		}
		q = q.Where(query.Job.AgentID.Eq(agentNumeric))
	}

	jobs, total, err := q.FindByPage(offset, limit)
	if err != nil {
		return nil, 0, err
	}
	items := make([]*model.Job, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, job)
	}
	return items, total, nil
}

func (r *jobRepository) ListByCursor(ctx context.Context, agentID string, cursorTime time.Time, cursorID string, limit int) ([]*model.Job, bool, error) {
	q := query.Job.WithContext(ctx).Order(query.Job.CreatedAt.Desc(), query.Job.ID.Desc())
	if trimmedAgentID := strings.TrimSpace(agentID); trimmedAgentID != "" {
		agentNumeric, err := strconv.ParseInt(trimmedAgentID, 10, 64)
		if err != nil {
			return []*model.Job{}, false, nil
		}
		q = q.Where(query.Job.AgentID.Eq(agentNumeric))
	}

	queryDB := q.UnderlyingDB()
	if !cursorTime.IsZero() && strings.TrimSpace(cursorID) != "" {
		queryDB = queryDB.Where("(created_at < ?) OR (created_at = ? AND id < ?)", cursorTime, cursorTime, strings.TrimSpace(cursorID))
	}

	var jobs []*model.Job
	if err := queryDB.Limit(limit + 1).Find(&jobs).Error; err != nil {
		return nil, false, err
	}

	hasMore := len(jobs) > limit
	if hasMore {
		jobs = jobs[:limit]
	}
	return jobs, hasMore, nil
}

func (r *jobRepository) Create(ctx context.Context, job *model.Job) error {
	return query.Job.WithContext(ctx).Create(job)
}

func (r *jobRepository) GetByID(ctx context.Context, id string) (*model.Job, error) {
	return query.Job.WithContext(ctx).Where(query.Job.ID.Eq(strings.TrimSpace(id))).First()
}

func (r *jobRepository) Save(ctx context.Context, job *model.Job) error {
	return query.Job.WithContext(ctx).Save(job)
}

func (r *jobRepository) UpdateVideoStatus(ctx context.Context, videoID string, statusValue string, processingStatus string) error {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" {
		return nil
	}
	_, err := query.Video.WithContext(ctx).
		Where(query.Video.ID.Eq(videoID)).
		Updates(map[string]any{"status": statusValue, "processing_status": processingStatus})
	return err
}

func (r *jobRepository) GetLatestByVideoID(ctx context.Context, videoID string) (*model.Job, error) {
	var job model.Job
	if err := r.db.WithContext(ctx).
		Where("config::jsonb ->> 'video_id' = ?", strings.TrimSpace(videoID)).
		Order("created_at DESC").
		First(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}
