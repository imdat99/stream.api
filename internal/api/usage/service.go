package usage

import (
	"context"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
)

func LoadUsage(ctx context.Context, db *gorm.DB, l logger.Logger, user *model.User) (*UsagePayload, error) {
	var totalVideos int64
	if err := db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", user.ID).Count(&totalVideos).Error; err != nil {
		l.Error("Failed to count user videos", "error", err, "user_id", user.ID)
		return nil, err
	}

	return &UsagePayload{
		UserID:       user.ID,
		TotalVideos:  totalVideos,
		TotalStorage: user.StorageUsed,
	}, nil
}
