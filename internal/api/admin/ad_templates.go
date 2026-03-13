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

	// "stream.api/internal/database/model"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

type AdminAdTemplatePayload struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	VastTagURL  string `json:"vast_tag_url"`
	AdFormat    string `json:"ad_format"`
	Duration    *int64 `json:"duration,omitempty"`
	IsActive    bool   `json:"is_active"`
	IsDefault   bool   `json:"is_default"`
	OwnerEmail  string `json:"owner_email,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type SaveAdminAdTemplateRequest struct {
	UserID      string `json:"user_id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	VASTTagURL  string `json:"vast_tag_url" binding:"required"`
	AdFormat    string `json:"ad_format"`
	Duration    *int64 `json:"duration"`
	IsActive    *bool  `json:"is_active"`
	IsDefault   *bool  `json:"is_default"`
}

func normalizeAdminAdFormat(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}

func unsetAdminDefaultTemplates(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.AdTemplate{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}

func validateAdminAdTemplateRequest(req *SaveAdminAdTemplateRequest) string {
	if strings.TrimSpace(req.UserID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.VASTTagURL) == "" {
		return "Name and VAST URL are required"
	}
	format := normalizeAdminAdFormat(req.AdFormat)
	if format == "mid-roll" && (req.Duration == nil || *req.Duration <= 0) {
		return "Duration is required for mid-roll templates"
	}
	return ""
}

func (h *Handler) buildAdminAdTemplatePayload(ctx *gin.Context, item model.AdTemplate, ownerEmail string) AdminAdTemplatePayload {
	return AdminAdTemplatePayload{
		ID:          item.ID,
		UserID:      item.UserID,
		Name:        item.Name,
		Description: adminStringValue(item.Description),
		VastTagURL:  item.VastTagURL,
		AdFormat:    adminStringValue(item.AdFormat),
		Duration:    item.Duration,
		IsActive:    adminBoolValue(item.IsActive, true),
		IsDefault:   item.IsDefault,
		OwnerEmail:  ownerEmail,
		CreatedAt:   adminFormatTime(item.CreatedAt),
		UpdatedAt:   adminFormatTime(item.UpdatedAt),
	}
}

// @Summary      List All Ad Templates
// @Description  Get paginated list of all ad templates across users (admin only)
// @Tags         admin
// @Produce      json
// @Param        page query int false "Page" default(1)
// @Param        limit query int false "Limit" default(20)
// @Param        user_id query string false "Filter by user ID"
// @Param        search query string false "Search by name"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Router       /admin/ad-templates [get]
// @Security     BearerAuth
func (h *Handler) ListAdTemplates(c *gin.Context) {
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

	db := h.db.WithContext(ctx).Model(&model.AdTemplate{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("name ILIKE ?", like)
	}
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to list ad templates")
		return
	}

	var templates []model.AdTemplate
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&templates).Error; err != nil {
		h.logger.Error("Failed to list ad templates", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list ad templates")
		return
	}

	ownerIDs := map[string]bool{}
	for _, t := range templates {
		ownerIDs[t.UserID] = true
	}
	ownerEmails := map[string]string{}
	if len(ownerIDs) > 0 {
		ids := make([]string, 0, len(ownerIDs))
		for id := range ownerIDs {
			ids = append(ids, id)
		}
		var users []struct{ ID, Email string }
		h.db.WithContext(ctx).Table("\"user\"").Select("id, email").Where("id IN ?", ids).Find(&users)
		for _, u := range users {
			ownerEmails[u.ID] = u.Email
		}
	}

	result := make([]AdminAdTemplatePayload, 0, len(templates))
	for _, t := range templates {
		result = append(result, h.buildAdminAdTemplatePayload(c, t, ownerEmails[t.UserID]))
	}

	response.Success(c, gin.H{
		"templates": result,
		"total":     total,
		"page":      page,
		"limit":     limit,
	})
}

// @Summary      Get Ad Template Detail
// @Description  Get ad template detail (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Ad Template ID"
// @Success      200  {object}  response.Response
// @Router       /admin/ad-templates/{id} [get]
// @Security     BearerAuth
func (h *Handler) GetAdTemplate(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Ad template not found")
		return
	}

	var item model.AdTemplate
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Ad template not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to load ad template")
		return
	}

	ownerEmail := ""
	var user model.User
	if err := h.db.WithContext(c.Request.Context()).Select("id, email").Where("id = ?", item.UserID).First(&user).Error; err == nil {
		ownerEmail = user.Email
	}

	response.Success(c, gin.H{"template": h.buildAdminAdTemplatePayload(c, item, ownerEmail)})
}

// @Summary      Create Ad Template
// @Description  Create an ad template for any user (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request body SaveAdminAdTemplateRequest true "Ad template payload"
// @Success      201  {object}  response.Response
// @Router       /admin/ad-templates [post]
// @Security     BearerAuth
func (h *Handler) CreateAdTemplate(c *gin.Context) {
	var req SaveAdminAdTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if msg := validateAdminAdTemplateRequest(&req); msg != "" {
		response.Error(c, http.StatusBadRequest, msg)
		return
	}

	ctx := c.Request.Context()
	var user model.User
	if err := h.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusBadRequest, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	item := &model.AdTemplate{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Name:        strings.TrimSpace(req.Name),
		Description: adminStringPtr(req.Description),
		VastTagURL:  strings.TrimSpace(req.VASTTagURL),
		AdFormat:    model.StringPtr(normalizeAdminAdFormat(req.AdFormat)),
		Duration:    req.Duration,
		IsActive:    model.BoolPtr(req.IsActive == nil || *req.IsActive),
		IsDefault:   req.IsDefault != nil && *req.IsDefault,
	}
	if !adminBoolValue(item.IsActive, true) {
		item.IsDefault = false
	}

	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := unsetAdminDefaultTemplates(tx, item.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		h.logger.Error("Failed to create ad template", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	response.Created(c, gin.H{"template": h.buildAdminAdTemplatePayload(c, *item, user.Email)})
}

// @Summary      Update Ad Template
// @Description  Update an ad template for any user (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "Ad Template ID"
// @Param        request body SaveAdminAdTemplateRequest true "Ad template payload"
// @Success      200  {object}  response.Response
// @Router       /admin/ad-templates/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdateAdTemplate(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Ad template not found")
		return
	}

	var req SaveAdminAdTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if msg := validateAdminAdTemplateRequest(&req); msg != "" {
		response.Error(c, http.StatusBadRequest, msg)
		return
	}

	ctx := c.Request.Context()
	var user model.User
	if err := h.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusBadRequest, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	var item model.AdTemplate
	if err := h.db.WithContext(ctx).Where("id = ?", id).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Ad template not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	item.UserID = user.ID
	item.Name = strings.TrimSpace(req.Name)
	item.Description = adminStringPtr(req.Description)
	item.VastTagURL = strings.TrimSpace(req.VASTTagURL)
	item.AdFormat = model.StringPtr(normalizeAdminAdFormat(req.AdFormat))
	item.Duration = req.Duration
	if req.IsActive != nil {
		item.IsActive = model.BoolPtr(*req.IsActive)
	}
	if req.IsDefault != nil {
		item.IsDefault = *req.IsDefault
	}
	if !adminBoolValue(item.IsActive, true) {
		item.IsDefault = false
	}

	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := unsetAdminDefaultTemplates(tx, item.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		h.logger.Error("Failed to update ad template", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to save ad template")
		return
	}

	response.Success(c, gin.H{"template": h.buildAdminAdTemplatePayload(c, item, user.Email)})
}

// @Summary      Delete Ad Template (Admin)
// @Description  Delete any ad template by ID (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Ad Template ID"
// @Success      200  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Router       /admin/ad-templates/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteAdTemplate(c *gin.Context) {
	id := c.Param("id")

	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("ad_template_id = ?", id).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		res := tx.Where("id = ?", id).Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "Ad template not found")
			return
		}
		h.logger.Error("Failed to delete ad template", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete ad template")
		return
	}

	response.Success(c, gin.H{"message": "Ad template deleted"})
}
