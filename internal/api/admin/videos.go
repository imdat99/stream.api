//go:build ignore
// +build ignore

package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

type AdminVideoPayload struct {
	ID             string  `json:"id"`
	UserID         string  `json:"user_id"`
	Title          string  `json:"title"`
	Description    string  `json:"description,omitempty"`
	URL            string  `json:"url"`
	Status         string  `json:"status"`
	Size           int64   `json:"size"`
	Duration       int32   `json:"duration"`
	Format         string  `json:"format"`
	OwnerEmail     string  `json:"owner_email,omitempty"`
	AdTemplateID   *string `json:"ad_template_id,omitempty"`
	AdTemplateName string  `json:"ad_template_name,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

type SaveAdminVideoRequest struct {
	UserID       string  `json:"user_id" binding:"required"`
	Title        string  `json:"title" binding:"required"`
	Description  string  `json:"description"`
	URL          string  `json:"url" binding:"required"`
	Size         int64   `json:"size" binding:"required"`
	Duration     int32   `json:"duration"`
	Format       string  `json:"format"`
	Status       string  `json:"status"`
	AdTemplateID *string `json:"ad_template_id,omitempty"`
}

func normalizeAdminVideoStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "processing", "pending":
		return "processing"
	case "failed", "error":
		return "failed"
	default:
		return "ready"
	}
}

func (h *Handler) loadAdminVideoPayload(ctx *gin.Context, video model.Video) (AdminVideoPayload, error) {
	payload := AdminVideoPayload{
		ID:          video.ID,
		UserID:      video.UserID,
		Title:       video.Title,
		Description: adminStringValue(video.Description),
		URL:         video.URL,
		Status:      adminStringValue(video.Status),
		Size:        video.Size,
		Duration:    video.Duration,
		Format:      video.Format,
		CreatedAt:   adminFormatTime(video.CreatedAt),
		UpdatedAt:   adminFormatTimeValue(video.UpdatedAt),
	}

	var user model.User
	if err := h.db.WithContext(ctx.Request.Context()).Select("id, email").Where("id = ?", video.UserID).First(&user).Error; err == nil {
		payload.OwnerEmail = user.Email
	}

	var adConfig model.VideoAdConfig
	if err := h.db.WithContext(ctx.Request.Context()).Where("video_id = ?", video.ID).First(&adConfig).Error; err == nil {
		payload.AdTemplateID = &adConfig.AdTemplateID
		var template model.AdTemplate
		if err := h.db.WithContext(ctx.Request.Context()).Where("id = ?", adConfig.AdTemplateID).First(&template).Error; err == nil {
			payload.AdTemplateName = template.Name
		}
	}

	return payload, nil
}

func (h *Handler) saveAdminVideoAdConfig(tx *gorm.DB, videoID, userID string, adTemplateID *string) error {
	if adTemplateID == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*adTemplateID)
	if trimmed == "" {
		return tx.Where("video_id = ? AND user_id = ?", videoID, userID).Delete(&model.VideoAdConfig{}).Error
	}

	var template model.AdTemplate
	if err := tx.Where("id = ? AND user_id = ?", trimmed, userID).First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &gin.Error{Err: errors.New("Ad template not found"), Type: gin.ErrorTypeBind}
		}
		return err
	}

	var existing model.VideoAdConfig
	if err := tx.Where("video_id = ? AND user_id = ?", videoID, userID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&model.VideoAdConfig{
				VideoID:      videoID,
				UserID:       userID,
				AdTemplateID: template.ID,
				VastTagURL:   template.VastTagURL,
				AdFormat:     template.AdFormat,
				Duration:     template.Duration,
			}).Error
		}
		return err
	}

	existing.AdTemplateID = template.ID
	existing.VastTagURL = template.VastTagURL
	existing.AdFormat = template.AdFormat
	existing.Duration = template.Duration
	return tx.Save(&existing).Error
}

// @Summary      List All Videos
// @Description  Get paginated list of all videos across users (admin only)
// @Tags         admin
// @Produce      json
// @Param        page query int false "Page" default(1)
// @Param        limit query int false "Limit" default(20)
// @Param        search query string false "Search by title"
// @Param        user_id query string false "Filter by user ID"
// @Param        status query string false "Filter by status"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Router       /admin/videos [get]
// @Security     BearerAuth
func (h *Handler) ListVideos(c *gin.Context) {
	ctx := c.Request.Context()
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	search := strings.TrimSpace(c.Query("search"))
	userID := strings.TrimSpace(c.Query("user_id"))
	status := strings.TrimSpace(c.Query("status"))

	db := h.db.WithContext(ctx).Model(&model.Video{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ?", like)
	}
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if status != "" && !strings.EqualFold(status, "all") {
		db = db.Where("status = ?", normalizeAdminVideoStatus(status))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to list videos")
		return
	}

	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&videos).Error; err != nil {
		h.logger.Error("Failed to list videos", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list videos")
		return
	}

	result := make([]AdminVideoPayload, 0, len(videos))
	for _, v := range videos {
		payload, err := h.loadAdminVideoPayload(c, v)
		if err != nil {
			response.Error(c, http.StatusInternalServerError, "Failed to list videos")
			return
		}
		result = append(result, payload)
	}

	response.Success(c, gin.H{
		"videos": result,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

// @Summary      Get Video Detail
// @Description  Get video detail by ID (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Video ID"
// @Success      200  {object}  response.Response
// @Router       /admin/videos/{id} [get]
// @Security     BearerAuth
func (h *Handler) GetVideo(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Video not found")
		return
	}

	var video model.Video
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to get video")
		return
	}

	payload, err := h.loadAdminVideoPayload(c, video)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to get video")
		return
	}

	response.Success(c, gin.H{"video": payload})
}

// @Summary      Create Video
// @Description  Create a model video record for a user (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request body SaveAdminVideoRequest true "Video payload"
// @Success      201  {object}  response.Response
// @Router       /admin/videos [post]
// @Security     BearerAuth
func (h *Handler) CreateVideo(c *gin.Context) {
	var req SaveAdminVideoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	if strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.URL) == "" {
		response.Error(c, http.StatusBadRequest, "User ID, title, and URL are required")
		return
	}
	if req.Size < 0 {
		response.Error(c, http.StatusBadRequest, "Size must be greater than or equal to 0")
		return
	}

	ctx := c.Request.Context()
	var user model.User
	if err := h.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusBadRequest, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to create video")
		return
	}

	status := normalizeAdminVideoStatus(req.Status)
	processingStatus := strings.ToUpper(status)
	storageType := "WORKER"
	video := &model.Video{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		Name:             strings.TrimSpace(req.Title),
		Title:            strings.TrimSpace(req.Title),
		Description:      adminStringPtr(req.Description),
		URL:              strings.TrimSpace(req.URL),
		Size:             req.Size,
		Duration:         req.Duration,
		Format:           strings.TrimSpace(req.Format),
		Status:           &status,
		ProcessingStatus: &processingStatus,
		StorageType:      &storageType,
	}

	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(video).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
			return err
		}
		if err := h.saveAdminVideoAdConfig(tx, video.ID, user.ID, req.AdTemplateID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "Ad template not found") {
			response.Error(c, http.StatusBadRequest, "Ad template not found")
			return
		}
		h.logger.Error("Failed to create video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create video")
		return
	}

	payload, err := h.loadAdminVideoPayload(c, *video)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to create video")
		return
	}

	response.Created(c, gin.H{"video": payload})
}

// @Summary      Update Video
// @Description  Update video metadata and status (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "Video ID"
// @Param        request body SaveAdminVideoRequest true "Video payload"
// @Success      200  {object}  response.Response
// @Router       /admin/videos/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdateVideo(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Video not found")
		return
	}

	var req SaveAdminVideoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.URL) == "" {
		response.Error(c, http.StatusBadRequest, "User ID, title, and URL are required")
		return
	}
	if req.Size < 0 {
		response.Error(c, http.StatusBadRequest, "Size must be greater than or equal to 0")
		return
	}

	ctx := c.Request.Context()
	var video model.Video
	if err := h.db.WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	var user model.User
	if err := h.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusBadRequest, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	oldSize := video.Size
	oldUserID := video.UserID
	status := normalizeAdminVideoStatus(req.Status)
	processingStatus := strings.ToUpper(status)
	video.UserID = user.ID
	video.Name = strings.TrimSpace(req.Title)
	video.Title = strings.TrimSpace(req.Title)
	video.Description = adminStringPtr(req.Description)
	video.URL = strings.TrimSpace(req.URL)
	video.Size = req.Size
	video.Duration = req.Duration
	video.Format = strings.TrimSpace(req.Format)
	video.Status = &status
	video.ProcessingStatus = &processingStatus

	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		if oldUserID != user.ID {
			if err := tx.Model(&model.VideoAdConfig{}).Where("video_id = ?", video.ID).Update("user_id", user.ID).Error; err != nil {
				return err
			}
		}
		if err := h.saveAdminVideoAdConfig(tx, video.ID, user.ID, req.AdTemplateID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "Ad template not found") {
			response.Error(c, http.StatusBadRequest, "Ad template not found")
			return
		}
		h.logger.Error("Failed to update video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	payload, err := h.loadAdminVideoPayload(c, video)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	response.Success(c, gin.H{"video": payload})
}

// @Summary      Delete Video (Admin)
// @Description  Delete any video by ID (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Video ID"
// @Success      200  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Router       /admin/videos/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteVideo(c *gin.Context) {
	id := c.Param("id")

	var video model.Video
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&video).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to find video")
		return
	}

	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("video_id = ?", video.ID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", video.ID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", video.UserID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", video.Size)).Error
	})
	if err != nil {
		h.logger.Error("Failed to delete video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete video")
		return
	}

	response.Success(c, gin.H{"message": "Video deleted"})
}
