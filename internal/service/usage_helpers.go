package service

import (
	"context"

	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
)

type usagePayload struct {
	UserID       string `json:"user_id"`
	TotalVideos  int64  `json:"total_videos"`
	TotalStorage int64  `json:"total_storage"`
}

func loadUsage(ctx context.Context, videoRepo VideoRepository, l logger.Logger, user *model.User) (*usagePayload, error) {
	totalVideos, err := videoRepo.CountByUser(ctx, user.ID)
	if err != nil {
		l.Error("Failed to count user videos", "error", err, "user_id", user.ID)
		return nil, err
	}

	return &usagePayload{
		UserID:       user.ID,
		TotalVideos:  totalVideos,
		TotalStorage: user.StorageUsed,
	}, nil
}
