package videos

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/modules/common"
	videodomain "stream.api/internal/video"
)

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) GetUploadURL(ctx context.Context, cmd GetUploadURLCommand) (*GetUploadURLResult, error) {
	storageProvider := m.runtime.StorageProvider()
	if storageProvider == nil {
		return nil, status.Error(codes.FailedPrecondition, "Storage provider is not configured")
	}
	filename := strings.TrimSpace(cmd.Filename)
	if filename == "" {
		return nil, status.Error(codes.InvalidArgument, "Filename is required")
	}
	fileID := uuid.New().String()
	key := fmt.Sprintf("videos/%s/%s-%s", cmd.UserID, fileID, filename)
	uploadURL, err := storageProvider.GeneratePresignedURL(key, 15*time.Minute)
	if err != nil {
		m.runtime.Logger().Error("Failed to generate upload URL", "error", err)
		return nil, status.Error(codes.Internal, "Storage error")
	}
	return &GetUploadURLResult{UploadURL: uploadURL, Key: key, FileID: fileID}, nil
}

func (m *Module) CreateVideo(ctx context.Context, cmd CreateVideoCommand) (*VideoView, error) {
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	title := strings.TrimSpace(cmd.Title)
	if title == "" {
		return nil, status.Error(codes.InvalidArgument, "Title is required")
	}
	videoURL := strings.TrimSpace(cmd.URL)
	if videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "URL is required")
	}
	description := strings.TrimSpace(cmd.Description)
	created, err := videoService.CreateVideo(ctx, videodomain.CreateVideoInput{UserID: cmd.UserID, Title: title, Description: &description, URL: videoURL, Size: cmd.Size, Duration: cmd.Duration, Format: strings.TrimSpace(cmd.Format)})
	if err != nil {
		m.runtime.Logger().Error("Failed to create video", "error", err)
		switch {
		case errors.Is(err, videodomain.ErrJobServiceUnavailable):
			return nil, status.Error(codes.Unavailable, "Job service is unavailable")
		default:
			return nil, status.Error(codes.Internal, "Failed to create video")
		}
	}
	jobID := created.Job.ID
	return &VideoView{Video: created.Video, JobID: &jobID}, nil
}

func (m *Module) ListVideos(ctx context.Context, queryValue ListVideosQuery) (*ListVideosResult, error) {
	page := queryValue.Page
	if page < 1 {
		page = 1
	}
	limit := queryValue.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := int((page - 1) * limit)
	db := m.runtime.DB().WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", queryValue.UserID)
	if search := strings.TrimSpace(queryValue.Search); search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ? OR description ILIKE ?", like, like)
	}
	if st := strings.TrimSpace(queryValue.StatusFilter); st != "" && !strings.EqualFold(st, "all") {
		db = db.Where("status = ?", common.NormalizeVideoStatusValue(st))
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		m.runtime.Logger().Error("Failed to count videos", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch videos")
	}
	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&videos).Error; err != nil {
		m.runtime.Logger().Error("Failed to list videos", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch videos")
	}
	items := make([]VideoView, 0, len(videos))
	for i := range videos {
		payload, err := m.BuildVideo(ctx, &videos[i])
		if err != nil {
			m.runtime.Logger().Error("Failed to build video payload", "error", err, "video_id", videos[i].ID)
			return nil, status.Error(codes.Internal, "Failed to fetch videos")
		}
		items = append(items, payload)
	}
	return &ListVideosResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetVideo(ctx context.Context, queryValue GetVideoQuery) (*VideoView, error) {
	id := strings.TrimSpace(queryValue.ID)
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	_ = m.runtime.DB().WithContext(ctx).Model(&model.Video{}).Where("id = ? AND user_id = ?", id, queryValue.UserID).UpdateColumn("views", gorm.Expr("views + ?", 1)).Error
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", id, queryValue.UserID).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		m.runtime.Logger().Error("Failed to fetch video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch video")
	}
	payload, err := m.BuildVideo(ctx, &video)
	if err != nil {
		m.runtime.Logger().Error("Failed to build video payload", "error", err, "video_id", video.ID)
		return nil, status.Error(codes.Internal, "Failed to fetch video")
	}
	return &payload, nil
}

func (m *Module) UpdateVideo(ctx context.Context, cmd UpdateVideoCommand) (*VideoView, error) {
	id := strings.TrimSpace(cmd.ID)
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	updates := map[string]any{}
	if title := strings.TrimSpace(cmd.Title); title != "" {
		updates["name"] = title
		updates["title"] = title
	}
	if cmd.Description != nil {
		desc := strings.TrimSpace(*cmd.Description)
		updates["description"] = common.NullableTrimmedString(&desc)
	}
	if urlValue := strings.TrimSpace(cmd.URL); urlValue != "" {
		updates["url"] = urlValue
	}
	if cmd.Size > 0 {
		updates["size"] = cmd.Size
	}
	if cmd.Duration > 0 {
		updates["duration"] = cmd.Duration
	}
	if cmd.Format != nil {
		updates["format"] = strings.TrimSpace(*cmd.Format)
	}
	if cmd.Status != nil {
		updates["status"] = common.NormalizeVideoStatusValue(*cmd.Status)
	}
	if len(updates) == 0 {
		return nil, status.Error(codes.InvalidArgument, "No changes provided")
	}
	res := m.runtime.DB().WithContext(ctx).Model(&model.Video{}).Where("id = ? AND user_id = ?", id, cmd.UserID).Updates(updates)
	if res.Error != nil {
		m.runtime.Logger().Error("Failed to update video", "error", res.Error)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	if res.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", id, cmd.UserID).First(&video).Error; err != nil {
		m.runtime.Logger().Error("Failed to reload video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	payload, err := m.BuildVideo(ctx, &video)
	if err != nil {
		m.runtime.Logger().Error("Failed to build video payload", "error", err, "video_id", video.ID)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	return &payload, nil
}

func (m *Module) DeleteVideo(ctx context.Context, cmd DeleteVideoCommand) error {
	id := strings.TrimSpace(cmd.ID)
	if id == "" {
		return status.Error(codes.NotFound, "Video not found")
	}
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", id, cmd.UserID).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.NotFound, "Video not found")
		}
		m.runtime.Logger().Error("Failed to load video", "error", err)
		return status.Error(codes.Internal, "Failed to delete video")
	}
	storageProvider := m.runtime.StorageProvider()
	if storageProvider != nil && common.ShouldDeleteStoredObject(video.URL) {
		if err := storageProvider.Delete(video.URL); err != nil {
			if parsedKey := common.ExtractObjectKey(video.URL); parsedKey != "" && parsedKey != video.URL {
				if deleteErr := storageProvider.Delete(parsedKey); deleteErr != nil {
					m.runtime.Logger().Error("Failed to delete video object", "error", deleteErr, "video_id", video.ID)
					return status.Error(codes.Internal, "Failed to delete video")
				}
			} else {
				m.runtime.Logger().Error("Failed to delete video object", "error", err, "video_id", video.ID)
				return status.Error(codes.Internal, "Failed to delete video")
			}
		}
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ? AND user_id = ?", video.ID, cmd.UserID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", cmd.UserID).UpdateColumn("storage_used", gorm.Expr("storage_used - ?", video.Size)).Error
	}); err != nil {
		m.runtime.Logger().Error("Failed to delete video", "error", err)
		return status.Error(codes.Internal, "Failed to delete video")
	}
	return nil
}

func (m *Module) ListAdminVideos(ctx context.Context, queryValue ListAdminVideosQuery) (*ListAdminVideosResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)
	limitInt := int(limit)
	db := m.runtime.DB().WithContext(ctx).Model(&model.Video{})
	if search := strings.TrimSpace(queryValue.Search); search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ?", like)
	}
	if userID := strings.TrimSpace(queryValue.UserID); userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if statusFilter := strings.TrimSpace(queryValue.StatusFilter); statusFilter != "" && !strings.EqualFold(statusFilter, "all") {
		db = db.Where("status = ?", common.NormalizeVideoStatusValue(statusFilter))
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list videos")
	}
	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&videos).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list videos")
	}
	items := make([]AdminVideoView, 0, len(videos))
	for i := range videos {
		payload, err := m.BuildAdminVideo(ctx, &videos[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list videos")
		}
		items = append(items, payload)
	}
	return &ListAdminVideosResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetAdminVideo(ctx context.Context, queryValue GetAdminVideoQuery) (*AdminVideoView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(queryValue.ID)
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get video")
	}
	payload, err := m.BuildAdminVideo(ctx, &video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get video")
	}
	return &payload, nil
}

func (m *Module) CreateAdminVideo(ctx context.Context, cmd CreateAdminVideoCommand) (*AdminVideoView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	userID := strings.TrimSpace(cmd.UserID)
	title := strings.TrimSpace(cmd.Title)
	videoURL := strings.TrimSpace(cmd.URL)
	if userID == "" || title == "" || videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID, title, and URL are required")
	}
	if cmd.Size < 0 {
		return nil, status.Error(codes.InvalidArgument, "Size must be greater than or equal to 0")
	}
	created, err := videoService.CreateVideo(ctx, videodomain.CreateVideoInput{UserID: userID, Title: title, Description: cmd.Description, URL: videoURL, Size: cmd.Size, Duration: cmd.Duration, Format: strings.TrimSpace(cmd.Format), AdTemplateID: cmd.AdTemplateID})
	if err != nil {
		switch {
		case errors.Is(err, videodomain.ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "User not found")
		case errors.Is(err, videodomain.ErrAdTemplateNotFound):
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		case errors.Is(err, videodomain.ErrJobServiceUnavailable):
			return nil, status.Error(codes.Unavailable, "Job service is unavailable")
		default:
			return nil, status.Error(codes.Internal, "Failed to create video")
		}
	}
	payload, err := m.BuildAdminVideo(ctx, created.Video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create video")
	}
	return &payload, nil
}

func (m *Module) UpdateAdminVideo(ctx context.Context, cmd UpdateAdminVideoCommand) (*AdminVideoView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(cmd.ID)
	userID := strings.TrimSpace(cmd.UserID)
	title := strings.TrimSpace(cmd.Title)
	videoURL := strings.TrimSpace(cmd.URL)
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	if userID == "" || title == "" || videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID, title, and URL are required")
	}
	if cmd.Size < 0 {
		return nil, status.Error(codes.InvalidArgument, "Size must be greater than or equal to 0")
	}
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	oldSize := video.Size
	oldUserID := video.UserID
	statusValue := common.NormalizeVideoStatusValue(cmd.Status)
	processingStatus := strings.ToUpper(statusValue)
	video.UserID = user.ID
	video.Name = title
	video.Title = title
	video.Description = common.NullableTrimmedString(cmd.Description)
	video.URL = videoURL
	video.Size = cmd.Size
	video.Duration = cmd.Duration
	video.Format = strings.TrimSpace(cmd.Format)
	video.Status = model.StringPtr(statusValue)
	video.ProcessingStatus = model.StringPtr(processingStatus)
	video.StorageType = model.StringPtr(common.DetectStorageType(videoURL))
	err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&video).Error; err != nil {
			return err
		}
		if oldUserID == user.ID {
			delta := video.Size - oldSize
			if delta != 0 {
				if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used + ?, 0)", delta)).Error; err != nil {
					return err
				}
			}
		} else {
			if err := tx.Model(&model.User{}).Where("id = ?", oldUserID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", oldSize)).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
				return err
			}
		}
		return m.saveAdminVideoAdConfig(ctx, tx, &video, user.ID, cmd.AdTemplateID)
	})
	if err != nil {
		if strings.Contains(err.Error(), "Ad template not found") {
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	payload, err := m.BuildAdminVideo(ctx, &video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	return &payload, nil
}

func (m *Module) DeleteAdminVideo(ctx context.Context, cmd DeleteAdminVideoCommand) error {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(cmd.ID)
	if id == "" {
		return status.Error(codes.NotFound, "Video not found")
	}
	var video model.Video
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.NotFound, "Video not found")
		}
		return status.Error(codes.Internal, "Failed to find video")
	}
	err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", video.ID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", video.UserID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", video.Size)).Error
	})
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete video")
	}
	return nil
}

func (m *Module) BuildVideo(ctx context.Context, video *model.Video) (VideoView, error) {
	if video == nil {
		return VideoView{}, nil
	}
	jobID, err := m.LoadLatestVideoJobID(ctx, video.ID)
	if err != nil {
		return VideoView{}, err
	}
	return VideoView{Video: video, JobID: jobID}, nil
}

func (m *Module) BuildAdminVideo(ctx context.Context, video *model.Video) (AdminVideoView, error) {
	if video == nil {
		return AdminVideoView{}, nil
	}
	statusValue := common.StringValue(video.Status)
	if statusValue == "" {
		statusValue = "ready"
	}
	jobID, err := m.LoadLatestVideoJobID(ctx, video.ID)
	if err != nil {
		return AdminVideoView{}, err
	}
	ownerEmail, err := m.loadAdminUserEmail(ctx, video.UserID)
	if err != nil {
		return AdminVideoView{}, err
	}
	adTemplateID, adTemplateName, err := m.loadAdminVideoAdTemplateDetails(ctx, video)
	if err != nil {
		return AdminVideoView{}, err
	}
	var createdAt *string
	if video.CreatedAt != nil {
		formatted := video.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	updated := video.UpdatedAt.UTC().Format(time.RFC3339)
	updatedAt := &updated
	return AdminVideoView{ID: video.ID, UserID: video.UserID, Title: video.Title, Description: common.NullableTrimmedString(video.Description), URL: video.URL, Status: strings.ToLower(statusValue), Size: video.Size, Duration: video.Duration, Format: video.Format, CreatedAt: createdAt, UpdatedAt: updatedAt, ProcessingStatus: common.NullableTrimmedString(video.ProcessingStatus), JobID: jobID, OwnerEmail: ownerEmail, AdTemplateID: adTemplateID, AdTemplateName: adTemplateName}, nil
}

func (m *Module) LoadLatestVideoJobID(ctx context.Context, videoID string) (*string, error) {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" {
		return nil, nil
	}
	var job model.Job
	if err := m.runtime.DB().WithContext(ctx).Where("config::jsonb ->> 'video_id' = ?", videoID).Order("created_at DESC").First(&job).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return common.StringPointerOrNil(job.ID), nil
}

func (m *Module) saveAdminVideoAdConfig(ctx context.Context, tx *gorm.DB, video *model.Video, userID string, adTemplateID *string) error {
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
			return errors.New("Ad template not found")
		}
		return err
	}
	if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", template.ID).Error; err != nil {
		return err
	}
	video.AdID = &template.ID
	return nil
}

func (m *Module) loadAdminUserEmail(ctx context.Context, userID string) (*string, error) {
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Select("id, email").Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return common.NullableTrimmedString(&user.Email), nil
}

func (m *Module) loadAdminVideoAdTemplateDetails(ctx context.Context, video *model.Video) (*string, *string, error) {
	if video == nil {
		return nil, nil, nil
	}
	adTemplateID := common.NullableTrimmedString(video.AdID)
	if adTemplateID == nil {
		return nil, nil, nil
	}
	adTemplateName, err := m.loadAdminAdTemplateName(ctx, *adTemplateID)
	if err != nil {
		return nil, nil, err
	}
	return adTemplateID, adTemplateName, nil
}

func (m *Module) loadAdminAdTemplateName(ctx context.Context, adTemplateID string) (*string, error) {
	var template model.AdTemplate
	if err := m.runtime.DB().WithContext(ctx).Select("id, name").Where("id = ?", adTemplateID).First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return common.NullableTrimmedString(&template.Name), nil
}
