//go:build ignore
// +build ignore

package video

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/storage"
)

type Handler struct {
	logger  logger.Logger
	cfg     *config.Config
	db      *gorm.DB
	storage storage.Provider
}

type videoError struct {
	Code    int
	Message string
}

func (e *videoError) Error() string { return e.Message }

func NewHandler(l logger.Logger, cfg *config.Config, db *gorm.DB, s storage.Provider) VideoHandler {
	return &Handler{
		logger:  l,
		cfg:     cfg,
		db:      db,
		storage: s,
	}
}

// @Summary      Get Upload URL
// @Description  Generate presigned URL for video upload
// @Tags         video
// @Accept       json
// @Produce      json
// @Param        request body UploadURLRequest true "File Info"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /videos/upload-url [post]
// @Security     BearerAuth
func (h *Handler) GetUploadURL(c *gin.Context) {
	var req UploadURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := c.GetString("userID")
	fileID := uuid.New().String()
	key := fmt.Sprintf("videos/%s/%s-%s", userID, fileID, req.Filename)

	url, err := h.storage.GeneratePresignedURL(key, 15*time.Minute)
	if err != nil {
		h.logger.Error("Failed to generate presigned URL", "error", err)
		response.Error(c, http.StatusInternalServerError, "Storage error")
		return
	}

	response.Success(c, gin.H{
		"upload_url": url,
		"key":        key,
		"file_id":    fileID,
	})
}

// @Summary      Create Video
// @Description  Create video record after upload
// @Tags         video
// @Accept       json
// @Produce      json
// @Param        request body CreateVideoRequest true "Video Info"
// @Success      201  {object}  response.Response{data=model.Video}
// @Failure      400  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /videos [post]
// @Security     BearerAuth
func (h *Handler) CreateVideo(c *gin.Context) {
	var req CreateVideoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		response.Error(c, http.StatusBadRequest, "Title is required")
		return
	}

	videoURL := strings.TrimSpace(req.URL)
	if videoURL == "" {
		response.Error(c, http.StatusBadRequest, "URL is required")
		return
	}

	status := "ready"
	processingStatus := "READY"
	storageType := detectStorageType(videoURL)
	description := strings.TrimSpace(req.Description)
	format := strings.TrimSpace(req.Format)

	video := &model.Video{
		ID:               uuid.New().String(),
		UserID:           userID,
		Name:             title,
		Title:            title,
		Description:      stringPointer(description),
		URL:              videoURL,
		Size:             req.Size,
		Duration:         req.Duration,
		Format:           format,
		Status:           &status,
		ProcessingStatus: &processingStatus,
		StorageType:      &storageType,
	}

	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var defaultTemplate model.AdTemplate
		hasDefaultTemplate := false

		if err := tx.Where("user_id = ? AND is_default = ? AND is_active = ?", userID, true, true).
			Order("updated_at DESC").
			First(&defaultTemplate).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		} else {
			hasDefaultTemplate = true
		}

		if err := tx.Create(video).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).
			Where("id = ?", userID).
			UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
			return err
		}

		if hasDefaultTemplate {
			videoAdConfig := &model.VideoAdConfig{
				VideoID:      video.ID,
				UserID:       userID,
				AdTemplateID: defaultTemplate.ID,
				VastTagURL:   defaultTemplate.VastTagURL,
				AdFormat:     defaultTemplate.AdFormat,
				Duration:     defaultTemplate.Duration,
			}

			if err := tx.Create(videoAdConfig).Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		h.logger.Error("Failed to create video record", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create video")
		return
	}

	response.Created(c, gin.H{"video": video})
}

// @Summary      List Videos
// @Description  Get paginated videos
// @Tags         video
// @Produce      json
// @Param        page query int false "Page number" default(1)
// @Param        limit query int false "Page size" default(10)
// @Success      200  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /videos [get]
// @Security     BearerAuth
func (h *Handler) ListVideos(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	search := strings.TrimSpace(c.Query("search"))
	status := strings.TrimSpace(c.Query("status"))

	db := h.db.WithContext(c.Request.Context()).Model(&model.Video{}).Where("user_id = ?", userID)
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ? OR description ILIKE ?", like, like)
	}
	if status != "" && !strings.EqualFold(status, "all") {
		db = db.Where("status = ?", normalizeVideoStatus(status))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		h.logger.Error("Failed to count videos", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch videos")
		return
	}

	var videos []*model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&videos).Error; err != nil {
		h.logger.Error("Failed to fetch videos", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch videos")
		return
	}

	response.Success(c, gin.H{
		"videos": videos,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

// @Summary      Get Video
// @Description  Get video details by ID
// @Tags         video
// @Produce      json
// @Param        id path string true "Video ID"
// @Success      200  {object}  response.Response{data=model.Video}
// @Failure      404  {object}  response.Response
// @Router       /videos/{id} [get]
// @Security     BearerAuth
func (h *Handler) GetVideo(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := c.Param("id")

	h.db.WithContext(c.Request.Context()).Model(&model.Video{}).
		Where("id = ? AND user_id = ?", id, userID).
		UpdateColumn("views", gorm.Expr("views + ?", 1))

	var video model.Video
	if err := h.db.WithContext(c.Request.Context()).Where("id = ? AND user_id = ?", id, userID).First(&video).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		h.logger.Error("Failed to fetch video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch video")
		return
	}

	result := gin.H{"video": &video}

	var adConfig model.VideoAdConfig
	if err := h.db.WithContext(c.Request.Context()).
		Where("video_id = ? AND user_id = ?", id, userID).
		First(&adConfig).Error; err == nil {
		adPayload := VideoAdConfigPayload{
			AdTemplateID: adConfig.AdTemplateID,
			VASTTagURL:   adConfig.VastTagURL,
			AdFormat:     model.StringValue(adConfig.AdFormat),
			Duration:     int64PtrToIntPtr(adConfig.Duration),
		}

		var template model.AdTemplate
		if err := h.db.WithContext(c.Request.Context()).
			Where("id = ? AND user_id = ?", adConfig.AdTemplateID, userID).
			First(&template).Error; err == nil {
			adPayload.TemplateName = template.Name
		}

		result["ad_config"] = adPayload
	}

	response.Success(c, result)
}

// @Summary      Update Video
// @Description  Update title and description for a video owned by the current user
// @Tags         video
// @Accept       json
// @Produce      json
// @Param        id path string true "Video ID"
// @Param        request body UpdateVideoRequest true "Video payload"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /videos/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdateVideo(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := c.Param("id")
	var req UpdateVideoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		response.Error(c, http.StatusBadRequest, "Title is required")
		return
	}
	description := strings.TrimSpace(req.Description)
	ctx := c.Request.Context()

	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.Video{}).
			Where("id = ? AND user_id = ?", id, userID).
			Updates(map[string]interface{}{
				"name":        title,
				"title":       title,
				"description": stringPointer(description),
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		if req.AdTemplateID != nil {
			templateID := strings.TrimSpace(*req.AdTemplateID)

			if templateID == "" {
				tx.Where("video_id = ? AND user_id = ?", id, userID).Delete(&model.VideoAdConfig{})
			} else {
				var template model.AdTemplate
				if err := tx.Where("id = ? AND user_id = ?", templateID, userID).
					First(&template).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						return &videoError{Code: http.StatusBadRequest, Message: "Ad template not found"}
					}
					return err
				}

				var existing model.VideoAdConfig
				if err := tx.Where("video_id = ? AND user_id = ?", id, userID).
					First(&existing).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						newConfig := &model.VideoAdConfig{
							VideoID:      id,
							UserID:       userID,
							AdTemplateID: template.ID,
							VastTagURL:   template.VastTagURL,
							AdFormat:     template.AdFormat,
							Duration:     template.Duration,
						}
						return tx.Create(newConfig).Error
					}
					return err
				}

				existing.AdTemplateID = template.ID
				existing.VastTagURL = template.VastTagURL
				existing.AdFormat = template.AdFormat
				existing.Duration = template.Duration
				return tx.Save(&existing).Error
			}
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		var ve *videoError
		if errors.As(err, &ve) {
			response.Error(c, ve.Code, ve.Message)
			return
		}
		h.logger.Error("Failed to update video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	var video model.Video
	if err := h.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).First(&video).Error; err != nil {
		h.logger.Error("Failed to reload video", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update video")
		return
	}

	resp := gin.H{"video": &video}

	var adConfig model.VideoAdConfig
	if err := h.db.WithContext(ctx).
		Where("video_id = ? AND user_id = ?", id, userID).
		First(&adConfig).Error; err == nil {
		adPayload := VideoAdConfigPayload{
			AdTemplateID: adConfig.AdTemplateID,
			VASTTagURL:   adConfig.VastTagURL,
			AdFormat:     model.StringValue(adConfig.AdFormat),
			Duration:     int64PtrToIntPtr(adConfig.Duration),
		}

		var template model.AdTemplate
		if err := h.db.WithContext(ctx).
			Where("id = ? AND user_id = ?", adConfig.AdTemplateID, userID).
			First(&template).Error; err == nil {
			adPayload.TemplateName = template.Name
		}

		resp["ad_config"] = adPayload
	}

	response.Success(c, resp)
}

// @Summary      Delete Video
// @Description  Delete a video owned by the current user
// @Tags         video
// @Produce      json
// @Param        id path string true "Video ID"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /videos/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteVideo(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := c.Param("id")
	var video model.Video
	if err := h.db.WithContext(c.Request.Context()).Where("id = ? AND user_id = ?", id, userID).First(&video).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Video not found")
			return
		}
		h.logger.Error("Failed to load video for deletion", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete video")
		return
	}

	if h.storage != nil && shouldDeleteStoredObject(video.URL) {
		if err := h.storage.Delete(video.URL); err != nil {
			parsedKey := extractObjectKey(video.URL)
			if parsedKey != "" && parsedKey != video.URL {
				if deleteErr := h.storage.Delete(parsedKey); deleteErr != nil {
					h.logger.Error("Failed to delete video object", "error", deleteErr, "video_id", video.ID)
					response.Error(c, http.StatusInternalServerError, "Failed to delete video")
					return
				}
			} else {
				h.logger.Error("Failed to delete video object", "error", err, "video_id", video.ID)
				response.Error(c, http.StatusInternalServerError, "Failed to delete video")
				return
			}
		}
	}

	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("video_id = ? AND user_id = ?", video.ID, userID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ? AND user_id = ?", video.ID, userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", userID).
			UpdateColumn("storage_used", gorm.Expr("storage_used - ?", video.Size)).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.logger.Error("Failed to delete video record", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete video")
		return
	}

	response.Success(c, gin.H{"message": "Video deleted successfully"})
}

func normalizeVideoStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "processing", "pending":
		return "processing"
	case "failed", "error":
		return "failed"
	default:
		return "ready"
	}
}

func detectStorageType(rawURL string) string {
	if shouldDeleteStoredObject(rawURL) {
		return "S3"
	}
	return "WORKER"
}

func shouldDeleteStoredObject(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return !strings.HasPrefix(trimmed, "/")
	}
	return parsed.Scheme == "" && parsed.Host == "" && !strings.HasPrefix(trimmed, "/")
}

func extractObjectKey(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if parsed.Scheme == "" && parsed.Host == "" {
		return strings.TrimPrefix(parsed.Path, "/")
	}
	return strings.TrimPrefix(parsed.Path, "/")
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func int64PtrToIntPtr(value *int64) *int {
	if value == nil {
		return nil
	}
	converted := int(*value)
	return &converted
}
