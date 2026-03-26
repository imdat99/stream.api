package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

type videoRepository struct {
	db *gorm.DB
}

func NewVideoRepository(db *gorm.DB) *videoRepository {
	return &videoRepository{db: db}
}

func (r *videoRepository) ListByUser(ctx context.Context, userID string, search string, status string, offset int, limit int) ([]model.Video, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", strings.TrimSpace(userID))
	if trimmedSearch := strings.TrimSpace(search); trimmedSearch != "" {
		like := "%" + trimmedSearch + "%"
		db = db.Where("title ILIKE ? OR description ILIKE ?", like, like)
	}
	if trimmedStatus := strings.TrimSpace(status); trimmedStatus != "" && !strings.EqualFold(trimmedStatus, "all") {
		db = db.Where("status = ?", trimmedStatus)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&videos).Error; err != nil {
		return nil, 0, err
	}

	return videos, total, nil
}

func (r *videoRepository) ListForAdmin(ctx context.Context, search string, userID string, status string, offset int, limit int) ([]model.Video, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.Video{})
	if trimmedSearch := strings.TrimSpace(search); trimmedSearch != "" {
		like := "%" + trimmedSearch + "%"
		db = db.Where("title ILIKE ?", like)
	}
	if trimmedUserID := strings.TrimSpace(userID); trimmedUserID != "" {
		db = db.Where("user_id = ?", trimmedUserID)
	}
	if trimmedStatus := strings.TrimSpace(status); trimmedStatus != "" && !strings.EqualFold(trimmedStatus, "all") {
		db = db.Where("status = ?", trimmedStatus)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&videos).Error; err != nil {
		return nil, 0, err
	}
	return videos, total, nil
}

func (r *videoRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.Video{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *videoRepository) CountCreatedSince(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.Video{}).Where("created_at >= ?", since).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *videoRepository) IncrementViews(ctx context.Context, videoID string, userID string) error {
	return r.db.WithContext(ctx).
		Model(&model.Video{}).
		Where("id = ? AND user_id = ?", strings.TrimSpace(videoID), strings.TrimSpace(userID)).
		UpdateColumn("views", gorm.Expr("views + ?", 1)).Error
}

func (r *videoRepository) GetByIDAndUser(ctx context.Context, videoID string, userID string) (*model.Video, error) {
	var video model.Video
	if err := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", strings.TrimSpace(videoID), strings.TrimSpace(userID)).
		First(&video).Error; err != nil {
		return nil, err
	}
	return &video, nil
}

func (r *videoRepository) GetByID(ctx context.Context, videoID string) (*model.Video, error) {
	var video model.Video
	if err := r.db.WithContext(ctx).
		Where("id = ?", strings.TrimSpace(videoID)).
		First(&video).Error; err != nil {
		return nil, err
	}
	return &video, nil
}

func (r *videoRepository) UpdateByIDAndUser(ctx context.Context, videoID string, userID string, updates map[string]any) (int64, error) {
	res := r.db.WithContext(ctx).
		Model(&model.Video{}).
		Where("id = ? AND user_id = ?", strings.TrimSpace(videoID), strings.TrimSpace(userID)).
		Updates(updates)
	return res.RowsAffected, res.Error
}

func (r *videoRepository) CountByUser(ctx context.Context, userID string) (int64, error) {
	var total int64
	err := r.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", strings.TrimSpace(userID)).Count(&total).Error
	return total, err
}

func (r *videoRepository) DeleteByIDAndUserWithStorageUpdate(ctx context.Context, videoID string, userID string, videoSize int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return r.deleteByIDAndUserWithStorageUpdateTx(tx, ctx, videoID, userID, videoSize)
	})
}

func (r *videoRepository) deleteByIDAndUserWithStorageUpdateTx(tx *gorm.DB, ctx context.Context, videoID string, userID string, videoSize int64) error {
	if err := tx.WithContext(ctx).Where("id = ? AND user_id = ?", strings.TrimSpace(videoID), strings.TrimSpace(userID)).Delete(&model.Video{}).Error; err != nil {
		return err
	}
	return tx.Model(&model.User{}).
		Where("id = ?", strings.TrimSpace(userID)).
		UpdateColumn("storage_used", gorm.Expr("storage_used - ?", videoSize)).Error
}

func (r *videoRepository) DeleteByIDWithStorageUpdate(ctx context.Context, videoID string, userID string, videoSize int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Where("id = ?", strings.TrimSpace(videoID)).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).
			Where("id = ?", strings.TrimSpace(userID)).
			UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", videoSize)).Error
	})
}

func (r *videoRepository) UpdateAdminVideo(ctx context.Context, video *model.Video, oldUserID string, oldSize int64, adTemplateID *string) error {
	if video == nil {
		return gorm.ErrInvalidData
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(video).Error; err != nil {
			return err
		}

		if strings.TrimSpace(oldUserID) == strings.TrimSpace(video.UserID) {
			delta := video.Size - oldSize
			if delta != 0 {
				if err := tx.Model(&model.User{}).
					Where("id = ?", strings.TrimSpace(video.UserID)).
					UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used + ?, 0)", delta)).Error; err != nil {
					return err
				}
			}
		} else {
			if err := tx.Model(&model.User{}).
				Where("id = ?", strings.TrimSpace(oldUserID)).
				UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", oldSize)).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.User{}).
				Where("id = ?", strings.TrimSpace(video.UserID)).
				UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
				return err
			}
		}

		if adTemplateID == nil {
			return nil
		}

		trimmedAdID := strings.TrimSpace(*adTemplateID)
		if trimmedAdID == "" {
			if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", nil).Error; err != nil {
				return err
			}
			video.AdID = nil
			return nil
		}

		var template model.AdTemplate
		if err := tx.WithContext(ctx).Select("id").Where("id = ? AND user_id = ?", trimmedAdID, strings.TrimSpace(video.UserID)).First(&template).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return gorm.ErrRecordNotFound
			}
			return err
		}
		if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", template.ID).Error; err != nil {
			return err
		}
		video.AdID = &template.ID
		return nil
	})
}
