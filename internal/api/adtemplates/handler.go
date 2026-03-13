//go:build ignore
// +build ignore

package adtemplates

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

const upgradeRequiredMessage = "Upgrade required to manage Ads & VAST"

type Handler struct {
	logger logger.Logger
	db     *gorm.DB
}

type SaveAdTemplateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	VASTTagURL  string `json:"vast_tag_url" binding:"required"`
	AdFormat    string `json:"ad_format"`
	Duration    *int   `json:"duration"`
	IsActive    *bool  `json:"is_active"`
	IsDefault   *bool  `json:"is_default"`
}

type TemplatePayload struct {
	Template *model.AdTemplate `json:"template"`
}

type TemplateListPayload struct {
	Templates []model.AdTemplate `json:"templates"`
}

func NewHandler(l logger.Logger, db *gorm.DB) *Handler {
	return &Handler{logger: l, db: db}
}

// @Summary      List Ad Templates
// @Description  Get all VAST ad templates for the current user
// @Tags         ad-templates
// @Produce      json
// @Success      200  {object}  response.Response{data=TemplateListPayload}
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /ad-templates [get]
// @Security     BearerAuth
func (h *Handler) ListTemplates(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var items []model.AdTemplate
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ?", userID).
		Order("is_default DESC").
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		h.logger.Error("Failed to list ad templates", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to load ad templates")
		return
	}

	response.Success(c, gin.H{"templates": items})
}

// @Summary      Create Ad Template
// @Description  Create a VAST ad template for the current user
// @Tags         ad-templates
// @Accept       json
// @Produce      json
// @Param        request body SaveAdTemplateRequest true "Ad template payload"
// @Success      201  {object}  response.Response{data=TemplatePayload}
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /ad-templates [post]
// @Security     BearerAuth
func (h *Handler) CreateTemplate(c *gin.Context) {
	h.saveTemplate(c, true)
}

// @Summary      Update Ad Template
// @Description  Update a VAST ad template for the current user
// @Tags         ad-templates
// @Accept       json
// @Produce      json
// @Param        id path string true "Ad Template ID"
// @Param        request body SaveAdTemplateRequest true "Ad template payload"
// @Success      200  {object}  response.Response{data=TemplatePayload}
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /ad-templates/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdateTemplate(c *gin.Context) {
	h.saveTemplate(c, false)
}

// @Summary      Delete Ad Template
// @Description  Delete a VAST ad template for the current user
// @Tags         ad-templates
// @Produce      json
// @Param        id path string true "Ad Template ID"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /ad-templates/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteTemplate(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !requirePaidPlan(c) {
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Ad template not found")
		return
	}

	result := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("ad_template_id = ? AND user_id = ?", id, userID).
			Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}

		res := tx.Where("id = ? AND user_id = ?", id, userID).Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if result != nil {
		if result == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Ad template not found")
			return
		}
		h.logger.Error("Failed to delete ad template", "error", result)
		response.Error(c, http.StatusInternalServerError, "Failed to delete ad template")
		return
	}

	response.Success(c, gin.H{"message": "Ad template deleted"})
}

func (h *Handler) saveTemplate(c *gin.Context, create bool) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !requirePaidPlan(c) {
		return
	}

	var req SaveAdTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	vastURL := strings.TrimSpace(req.VASTTagURL)
	if name == "" || vastURL == "" {
		response.Error(c, http.StatusBadRequest, "Name and VAST URL are required")
		return
	}

	format := normalizeAdFormat(req.AdFormat)
	if format == "mid-roll" && (req.Duration == nil || *req.Duration <= 0) {
		response.Error(c, http.StatusBadRequest, "Duration is required for mid-roll templates")
		return
	}

	ctx := c.Request.Context()
	if create {
		item := &model.AdTemplate{
			ID:          uuid.New().String(),
			UserID:      userID,
			Name:        name,
			Description: stringPointer(strings.TrimSpace(req.Description)),
			VastTagURL:  vastURL,
			AdFormat:    model.StringPtr(format),
			Duration:    intPtrToInt64Ptr(req.Duration),
			IsActive:    model.BoolPtr(req.IsActive == nil || *req.IsActive),
			IsDefault:   req.IsDefault != nil && *req.IsDefault,
		}
		if !adTemplateIsActive(item.IsActive) {
			item.IsDefault = false
		}

		if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if item.IsDefault {
				if err := unsetDefaultTemplates(tx, userID, ""); err != nil {
					return err
				}
			}

			return tx.Create(item).Error
		}); err != nil {
			h.logger.Error("Failed to create ad template", "error", err)
			response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
			return
		}

		response.Created(c, gin.H{"template": item})
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Ad template not found")
		return
	}

	var item model.AdTemplate
	if err := h.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).First(&item).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Ad template not found")
			return
		}
		h.logger.Error("Failed to load ad template", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	item.Name = name
	item.Description = stringPointer(strings.TrimSpace(req.Description))
	item.VastTagURL = vastURL
	item.AdFormat = model.StringPtr(format)
	item.Duration = intPtrToInt64Ptr(req.Duration)
	if req.IsActive != nil {
		item.IsActive = model.BoolPtr(*req.IsActive)
	}
	if req.IsDefault != nil {
		item.IsDefault = *req.IsDefault
	}
	if !adTemplateIsActive(item.IsActive) {
		item.IsDefault = false
	}

	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := unsetDefaultTemplates(tx, userID, item.ID); err != nil {
				return err
			}
		}

		return tx.Save(&item).Error
	}); err != nil {
		h.logger.Error("Failed to update ad template", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	response.Success(c, gin.H{"template": item})
}

func requirePaidPlan(c *gin.Context) bool {
	userValue, exists := c.Get("user")
	if !exists {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return false
	}

	user, ok := userValue.(*model.User)
	if !ok || user == nil {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return false
	}

	if user.PlanID == nil || strings.TrimSpace(*user.PlanID) == "" {
		response.Error(c, http.StatusForbidden, upgradeRequiredMessage)
		return false
	}

	return true
}

func unsetDefaultTemplates(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.AdTemplate{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}

	return query.Update("is_default", false).Error
}

func normalizeAdFormat(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func intPtrToInt64Ptr(value *int) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func adTemplateIsActive(value *bool) bool {
	return value == nil || *value
}
