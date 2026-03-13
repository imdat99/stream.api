//go:build ignore
// +build ignore

package domains

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	db     *gorm.DB
}

type CreateDomainRequest struct {
	Name string `json:"name" binding:"required"`
}

func NewHandler(l logger.Logger, db *gorm.DB) *Handler {
	return &Handler{logger: l, db: db}
}

// @Summary      List Domains
// @Description  Get all whitelisted domains for the current user
// @Tags         domains
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /domains [get]
// @Security     BearerAuth
func (h *Handler) ListDomains(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var items []model.Domain
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		h.logger.Error("Failed to list domains", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to load domains")
		return
	}

	response.Success(c, gin.H{"domains": items})
}

// @Summary      Create Domain
// @Description  Add a domain to the current user's whitelist
// @Tags         domains
// @Accept       json
// @Produce      json
// @Param        request body CreateDomainRequest true "Domain payload"
// @Success      201  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /domains [post]
// @Security     BearerAuth
func (h *Handler) CreateDomain(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	name := normalizeDomain(req.Name)
	if name == "" || !strings.Contains(name, ".") || strings.ContainsAny(name, "/ ") {
		response.Error(c, http.StatusBadRequest, "Invalid domain")
		return
	}

	var count int64
	if err := h.db.WithContext(c.Request.Context()).
		Model(&model.Domain{}).
		Where("user_id = ? AND name = ?", userID, name).
		Count(&count).Error; err != nil {
		h.logger.Error("Failed to validate domain", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create domain")
		return
	}
	if count > 0 {
		response.Error(c, http.StatusBadRequest, "Domain already exists")
		return
	}

	item := &model.Domain{
		ID:     uuid.New().String(),
		UserID: userID,
		Name:   name,
	}
	if err := h.db.WithContext(c.Request.Context()).Create(item).Error; err != nil {
		h.logger.Error("Failed to create domain", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create domain")
		return
	}

	response.Created(c, gin.H{"domain": item})
}

// @Summary      Delete Domain
// @Description  Remove a domain from the current user's whitelist
// @Tags         domains
// @Produce      json
// @Param        id path string true "Domain ID"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /domains/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteDomain(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Domain not found")
		return
	}

	result := h.db.WithContext(c.Request.Context()).
		Where("id = ? AND user_id = ?", id, userID).
		Delete(&model.Domain{})
	if result.Error != nil {
		h.logger.Error("Failed to delete domain", "error", result.Error)
		response.Error(c, http.StatusInternalServerError, "Failed to delete domain")
		return
	}
	if result.RowsAffected == 0 {
		response.Error(c, http.StatusNotFound, "Domain not found")
		return
	}

	response.Success(c, gin.H{"message": "Domain deleted"})
}

func normalizeDomain(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, "/")
	return normalized
}
