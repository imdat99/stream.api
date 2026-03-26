package service

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
	appv1 "stream.api/internal/api/proto/app/v1"
)

func (s *videosAppService) GetUploadUrl(ctx context.Context, req *appv1.GetUploadUrlRequest) (*appv1.GetUploadUrlResponse, error) {
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
func (s *videosAppService) CreateVideo(ctx context.Context, req *appv1.CreateVideoRequest) (*appv1.CreateVideoResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if s.videoWorkflowService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	title := strings.TrimSpace(req.GetTitle())
	if title == "" {
		return nil, status.Error(codes.InvalidArgument, "Title is required")
	}
	videoURL := strings.TrimSpace(req.GetUrl())
	if videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "URL is required")
	}
	description := strings.TrimSpace(req.GetDescription())

	created, err := s.videoWorkflowService.CreateVideo(ctx, CreateVideoInput{
		UserID:      result.UserID,
		Title:       title,
		Description: &description,
		URL:         videoURL,
		Size:        req.GetSize(),
		Duration:    req.GetDuration(),
		Format:      strings.TrimSpace(req.GetFormat()),
	})
	if err != nil {
		s.logger.Error("Failed to create video", "error", err)
		switch {
		case errors.Is(err, ErrJobServiceUnavailable):
			return nil, status.Error(codes.Unavailable, "Job service is unavailable")
		default:
			return nil, status.Error(codes.Internal, "Failed to create video")
		}
	}

	return &appv1.CreateVideoResponse{Video: toProtoVideo(created.Video, created.Job.ID)}, nil
}
func (s *videosAppService) ListVideos(ctx context.Context, req *appv1.ListVideosRequest) (*appv1.ListVideosResponse, error) {
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
	if s.videoRepository == nil {
		return nil, status.Error(codes.Internal, "Video repository is unavailable")
	}

	videos, total, err := s.videoRepository.ListByUser(ctx, result.UserID, req.GetSearch(), normalizeVideoStatusFilter(req.GetStatus()), offset, int(limit))
	if err != nil {
		s.logger.Error("Failed to list videos", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch videos")
	}

	items := make([]*appv1.Video, 0, len(videos))
	for i := range videos {
		payload, err := s.buildVideo(ctx, &videos[i])
		if err != nil {
			s.logger.Error("Failed to build video payload", "error", err, "video_id", videos[i].ID)
			return nil, status.Error(codes.Internal, "Failed to fetch videos")
		}
		items = append(items, payload)
	}

	return &appv1.ListVideosResponse{Videos: items, Total: total, Page: page, Limit: limit}, nil
}
func (s *videosAppService) GetVideo(ctx context.Context, req *appv1.GetVideoRequest) (*appv1.GetVideoResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	if s.videoRepository == nil {
		return nil, status.Error(codes.Internal, "Video repository is unavailable")
	}

	_ = s.videoRepository.IncrementViews(ctx, id, result.UserID)

	video, err := s.videoRepository.GetByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		s.logger.Error("Failed to fetch video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch video")
	}

	payload, err := s.buildVideo(ctx, video)
	if err != nil {
		s.logger.Error("Failed to build video payload", "error", err, "video_id", video.ID)
		return nil, status.Error(codes.Internal, "Failed to fetch video")
	}
	return &appv1.GetVideoResponse{Video: payload}, nil
}
func (s *videosAppService) UpdateVideo(ctx context.Context, req *appv1.UpdateVideoRequest) (*appv1.UpdateVideoResponse, error) {
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

	if s.videoRepository == nil {
		return nil, status.Error(codes.Internal, "Video repository is unavailable")
	}

	rowsAffected, err := s.videoRepository.UpdateByIDAndUser(ctx, id, result.UserID, updates)
	if err != nil {
		s.logger.Error("Failed to update video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	video, err := s.videoRepository.GetByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		s.logger.Error("Failed to reload video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	payload, err := s.buildVideo(ctx, video)
	if err != nil {
		s.logger.Error("Failed to build video payload", "error", err, "video_id", video.ID)
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	return &appv1.UpdateVideoResponse{Video: payload}, nil
}
func (s *videosAppService) DeleteVideo(ctx context.Context, req *appv1.DeleteVideoRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	if s.videoRepository == nil {
		return nil, status.Error(codes.Internal, "Video repository is unavailable")
	}

	video, err := s.videoRepository.GetByIDAndUser(ctx, id, result.UserID)
	if err != nil {
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

	if err := s.videoRepository.DeleteByIDAndUserWithStorageUpdate(ctx, video.ID, result.UserID, video.Size); err != nil {
		s.logger.Error("Failed to delete video", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete video")
	}

	return messageResponse("Video deleted successfully"), nil
}
