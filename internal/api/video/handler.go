package video

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/storage"
)

type Handler struct {
	logger  logger.Logger
	cfg     *config.Config
	storage storage.Provider
}

func NewHandler(l logger.Logger, cfg *config.Config, s storage.Provider) VideoHandler {
	return &Handler{
		logger:  l,
		cfg:     cfg,
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
		"file_id":    fileID, // Temporary ID, actual video record ID might differ or be same
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

	status := "PUBLIC"
	storageType := "S3"

	video := &model.Video{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        req.Title,
		Title:       req.Title,
		Description: &req.Description,
		URL:         req.URL,
		Size:        req.Size,
		Duration:    req.Duration,
		Format:      req.Format,
		Status:      &status,
		StorageType: &storageType,
	}

	q := query.Q
	err := q.Transaction(func(tx *query.Query) error {
		if err := tx.Video.WithContext(c.Request.Context()).Create(video); err != nil {
			return err
		}

		// Atomic update: StorageUsed = StorageUsed + video.Size
		// We use UpdateSimple with Add to ensure atomicity at database level: UPDATE users SET storage_used = storage_used + ?
		if _, err := tx.User.WithContext(c.Request.Context()).
			Where(tx.User.ID.Eq(userID)).
			UpdateSimple(tx.User.StorageUsed.Add(video.Size)); err != nil {
			return err
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
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset := (page - 1) * limit

	v := query.Video
	videos, count, err := v.WithContext(c.Request.Context()).
		Where(v.Status.Eq("PUBLIC")).
		Order(v.CreatedAt.Desc()).
		FindByPage(offset, limit)

	if err != nil {
		h.logger.Error("Failed to fetch videos", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch videos")
		return
	}

	response.Success(c, gin.H{
		"videos": videos,
		"total":  count,
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
	id := c.Param("id")
	v := query.Video

	// Atomically increment views: UPDATE videos SET views = views + 1 WHERE id = ?
	// We intentionally ignore errors here (like record not found) because the subsequent fetch will handle 404s,
	// and we don't want to fail the read if writing the view count fails for some transient reason.
	v.WithContext(c.Request.Context()).Where(v.ID.Eq(id)).UpdateSimple(v.Views.Add(1))

	video, err := v.WithContext(c.Request.Context()).Where(v.ID.Eq(id)).First()
	if err != nil {
		response.Error(c, http.StatusNotFound, "Video not found")
		return
	}

	response.Success(c, gin.H{"video": video})
}
