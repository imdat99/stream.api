package repository

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type videoWorkflowRepository struct {
	db *gorm.DB
}

func NewVideoWorkflowRepository(db *gorm.DB) *videoWorkflowRepository {
	return &videoWorkflowRepository{db: db}
}

func (r *videoWorkflowRepository) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(userID)).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *videoWorkflowRepository) CreateVideoWithStorageAndAd(ctx context.Context, video *model.Video, userID string, adTemplateID *string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(video).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", strings.TrimSpace(userID)).
			UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
			return err
		}
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
		if err := tx.WithContext(ctx).Select("id").Where("id = ? AND user_id = ?", trimmed, strings.TrimSpace(userID)).First(&template).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", template.ID).Error; err != nil {
			return err
		}
		video.AdID = &template.ID
		return nil
	})
}

func (r *videoWorkflowRepository) MarkVideoJobFailed(ctx context.Context, videoID string) error {
	return r.db.WithContext(ctx).
		Model(&model.Video{}).
		Where("id = ?", strings.TrimSpace(videoID)).
		Updates(map[string]any{"status": "failed", "processing_status": "FAILED"}).Error
}
