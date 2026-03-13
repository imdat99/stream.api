//go:build ignore
// +build ignore

package notifications

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	db     *gorm.DB
}

type NotificationItem struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Read        bool      `json:"read"`
	ActionURL   string    `json:"actionUrl,omitempty"`
	ActionLabel string    `json:"actionLabel,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func NewHandler(l logger.Logger, db *gorm.DB) *Handler {
	return &Handler{logger: l, db: db}
}

// @Summary      List Notifications
// @Description  Get notifications for the current user
// @Tags         notifications
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /notifications [get]
// @Security     BearerAuth
func (h *Handler) ListNotifications(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var rows []model.Notification
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		h.logger.Error("Failed to list notifications", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to load notifications")
		return
	}

	items := make([]NotificationItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, mapNotification(row))
	}

	response.Success(c, gin.H{"notifications": items})
}

// @Summary      Mark Notification Read
// @Description  Mark a single notification as read for the current user
// @Tags         notifications
// @Produce      json
// @Param        id path string true "Notification ID"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /notifications/{id}/read [post]
// @Security     BearerAuth
func (h *Handler) MarkRead(c *gin.Context) {
	h.updateReadState(c, true, false)
}

// @Summary      Mark All Notifications Read
// @Description  Mark all notifications as read for the current user
// @Tags         notifications
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /notifications/read-all [post]
// @Security     BearerAuth
func (h *Handler) MarkAllRead(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := h.db.WithContext(c.Request.Context()).
		Model(&model.Notification{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Update("is_read", true).Error; err != nil {
		h.logger.Error("Failed to mark all notifications as read", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update notifications")
		return
	}

	response.Success(c, gin.H{"message": "All notifications marked as read"})
}

// @Summary      Delete Notification
// @Description  Delete a single notification for the current user
// @Tags         notifications
// @Produce      json
// @Param        id path string true "Notification ID"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /notifications/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteNotification(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Notification not found")
		return
	}

	result := h.db.WithContext(c.Request.Context()).
		Where("id = ? AND user_id = ?", id, userID).
		Delete(&model.Notification{})
	if result.Error != nil {
		h.logger.Error("Failed to delete notification", "error", result.Error)
		response.Error(c, http.StatusInternalServerError, "Failed to delete notification")
		return
	}
	if result.RowsAffected == 0 {
		response.Error(c, http.StatusNotFound, "Notification not found")
		return
	}

	response.Success(c, gin.H{"message": "Notification deleted"})
}

// @Summary      Clear Notifications
// @Description  Delete all notifications for the current user
// @Tags         notifications
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /notifications [delete]
// @Security     BearerAuth
func (h *Handler) ClearNotifications(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := h.db.WithContext(c.Request.Context()).Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
		h.logger.Error("Failed to clear notifications", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to clear notifications")
		return
	}

	response.Success(c, gin.H{"message": "All notifications deleted"})
}

func (h *Handler) updateReadState(c *gin.Context, value bool, silentNotFound bool) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Notification not found")
		return
	}

	result := h.db.WithContext(c.Request.Context()).
		Model(&model.Notification{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_read", value)
	if result.Error != nil {
		h.logger.Error("Failed to update notification", "error", result.Error)
		response.Error(c, http.StatusInternalServerError, "Failed to update notification")
		return
	}
	if result.RowsAffected == 0 && !silentNotFound {
		response.Error(c, http.StatusNotFound, "Notification not found")
		return
	}

	response.Success(c, gin.H{"message": "Notification updated"})
}

func mapNotification(item model.Notification) NotificationItem {
	createdAt := time.Time{}
	if item.CreatedAt != nil {
		createdAt = item.CreatedAt.UTC()
	}

	return NotificationItem{
		ID:          item.ID,
		Type:        normalizeType(item.Type),
		Title:       item.Title,
		Message:     item.Message,
		Read:        item.IsRead,
		ActionURL:   model.StringValue(item.ActionURL),
		ActionLabel: model.StringValue(item.ActionLabel),
		CreatedAt:   createdAt,
	}
}

func normalizeType(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(lower, "video"):
		return "video"
	case strings.Contains(lower, "payment"), strings.Contains(lower, "billing"):
		return "payment"
	case strings.Contains(lower, "warning"):
		return "warning"
	case strings.Contains(lower, "error"):
		return "error"
	case strings.Contains(lower, "success"):
		return "success"
	case strings.Contains(lower, "system"):
		return "system"
	default:
		return "info"
	}
}
