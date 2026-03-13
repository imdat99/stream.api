package app

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
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func (s *appServices) GetUploadUrl(ctx context.Context, req *appv1.GetUploadUrlRequest) (*appv1.GetUploadUrlResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if s.storageProvider == nil {
		return nil, status.Error(codes.FailedPrecondition, "Storage provider is not configured")
	}

	filename := strings.TrimSpace(req.GetFilename())
	if filename == "" {
		return nil, status.Error(codes.InvalidArgument, "Filename is required")
	}

	fileID := uuid.New().String()
	key := fmt.Sprintf("videos/%s/%s-%s", result.UserID, fileID, filename)
	uploadURL, err := s.storageProvider.GeneratePresignedURL(key, 15*time.Minute)
	if err != nil {
		s.logger.Error("Failed to generate upload URL", "error", err)
		return nil, status.Error(codes.Internal, "Storage error")
	}

	return &appv1.GetUploadUrlResponse{UploadUrl: uploadURL, Key: key, FileId: fileID}, nil
}
func (s *appServices) CreateVideo(ctx context.Context, req *appv1.CreateVideoRequest) (*appv1.CreateVideoResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	title := strings.TrimSpace(req.GetTitle())
	if title == "" {
		return nil, status.Error(codes.InvalidArgument, "Title is required")
	}
	videoURL := strings.TrimSpace(req.GetUrl())
	if videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "URL is required")
	}

	statusValue := "ready"
	processingStatus := "READY"
	storageType := detectStorageType(videoURL)
	description := strings.TrimSpace(req.GetDescription())
	format := strings.TrimSpace(req.GetFormat())

	video := &model.Video{
		ID:               uuid.New().String(),
		UserID:           result.UserID,
		Name:             title,
		Title:            title,
		Description:      nullableTrimmedString(&description),
		URL:              videoURL,
		Size:             req.GetSize(),
		Duration:         req.GetDuration(),
		Format:           format,
		Status:           &statusValue,
		ProcessingStatus: &processingStatus,
		StorageType:      &storageType,
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(video).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).
			Where("id = ?", result.UserID).
			UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error
	}); err != nil {
		s.logger.Error("Failed to create video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create video")
	}

	return &appv1.CreateVideoResponse{Video: toProtoVideo(video)}, nil
}
func (s *appServices) ListVideos(ctx context.Context, req *appv1.ListVideosRequest) (*appv1.ListVideosResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	page := req.GetPage()
	if page < 1 {
		page = 1
	}
	limit := req.GetLimit()
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := int((page - 1) * limit)

	db := s.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", result.UserID)
	if search := strings.TrimSpace(req.GetSearch()); search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ? OR description ILIKE ?", like, like)
	}
	if st := strings.TrimSpace(req.GetStatus()); st != "" && !strings.EqualFold(st, "all") {
		db = db.Where("status = ?", normalizeVideoStatusValue(st))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		s.logger.Error("Failed to count videos", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch videos")
	}

	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&videos).Error; err != nil {
		s.logger.Error("Failed to list videos", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch videos")
	}

	items := make([]*appv1.Video, 0, len(videos))
	for i := range videos {
		items = append(items, toProtoVideo(&videos[i]))
	}

	return &appv1.ListVideosResponse{Videos: items, Total: total, Page: page, Limit: limit}, nil
}
func (s *appServices) GetVideo(ctx context.Context, req *appv1.GetVideoRequest) (*appv1.GetVideoResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	_ = s.db.WithContext(ctx).Model(&model.Video{}).
		Where("id = ? AND user_id = ?", id, result.UserID).
		UpdateColumn("views", gorm.Expr("views + ?", 1)).Error

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, result.UserID).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		s.logger.Error("Failed to fetch video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch video")
	}

	return &appv1.GetVideoResponse{Video: toProtoVideo(&video)}, nil
}
func (s *appServices) UpdateVideo(ctx context.Context, req *appv1.UpdateVideoRequest) (*appv1.UpdateVideoResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	updates := map[string]any{}
	if title := strings.TrimSpace(req.GetTitle()); title != "" {
		updates["name"] = title
		updates["title"] = title
	}
	if req.Description != nil {
		desc := strings.TrimSpace(req.GetDescription())
		updates["description"] = nullableTrimmedString(&desc)
	}
	if urlValue := strings.TrimSpace(req.GetUrl()); urlValue != "" {
		updates["url"] = urlValue
	}
	if req.Size > 0 {
		updates["size"] = req.GetSize()
	}
	if req.Duration > 0 {
		updates["duration"] = req.GetDuration()
	}
	if req.Format != nil {
		updates["format"] = strings.TrimSpace(req.GetFormat())
	}
	if req.Status != nil {
		updates["status"] = normalizeVideoStatusValue(req.GetStatus())
	}
	if len(updates) == 0 {
		return nil, status.Error(codes.InvalidArgument, "No changes provided")
	}

	res := s.db.WithContext(ctx).
		Model(&model.Video{}).
		Where("id = ? AND user_id = ?", id, result.UserID).
		Updates(updates)
	if res.Error != nil {
		s.logger.Error("Failed to update video", "error", res.Error)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	if res.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, result.UserID).First(&video).Error; err != nil {
		s.logger.Error("Failed to reload video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	return &appv1.UpdateVideoResponse{Video: toProtoVideo(&video)}, nil
}
func (s *appServices) DeleteVideo(ctx context.Context, req *appv1.DeleteVideoRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, result.UserID).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		s.logger.Error("Failed to load video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete video")
	}

	if s.storageProvider != nil && shouldDeleteStoredObject(video.URL) {
		if err := s.storageProvider.Delete(video.URL); err != nil {
			if parsedKey := extractObjectKey(video.URL); parsedKey != "" && parsedKey != video.URL {
				if deleteErr := s.storageProvider.Delete(parsedKey); deleteErr != nil {
					s.logger.Error("Failed to delete video object", "error", deleteErr, "video_id", video.ID)
					return nil, status.Error(codes.Internal, "Failed to delete video")
				}
			} else {
				s.logger.Error("Failed to delete video object", "error", err, "video_id", video.ID)
				return nil, status.Error(codes.Internal, "Failed to delete video")
			}
		}
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("video_id = ? AND user_id = ?", video.ID, result.UserID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ? AND user_id = ?", video.ID, result.UserID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).
			Where("id = ?", result.UserID).
			UpdateColumn("storage_used", gorm.Expr("storage_used - ?", video.Size)).Error
	}); err != nil {
		s.logger.Error("Failed to delete video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete video")
	}

	return messageResponse("Video deleted successfully"), nil
}
