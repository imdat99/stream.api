//go:build ignore
// +build ignore

package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

type AdminPlanPayload struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	Features          []string `json:"features,omitempty"`
	Price             float64  `json:"price"`
	Cycle             string   `json:"cycle"`
	StorageLimit      int64    `json:"storage_limit"`
	UploadLimit       int32    `json:"upload_limit"`
	DurationLimit     int32    `json:"duration_limit"`
	QualityLimit      string   `json:"quality_limit"`
	IsActive          bool     `json:"is_active"`
	UserCount         int64    `json:"user_count"`
	PaymentCount      int64    `json:"payment_count"`
	SubscriptionCount int64    `json:"subscription_count"`
}

type SavePlanRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  string   `json:"description"`
	Features     []string `json:"features"`
	Price        float64  `json:"price" binding:"required"`
	Cycle        string   `json:"cycle" binding:"required"`
	StorageLimit int64    `json:"storage_limit" binding:"required"`
	UploadLimit  int32    `json:"upload_limit" binding:"required"`
	IsActive     *bool    `json:"is_active"`
}

func buildAdminPlanPayload(plan model.Plan, userCount, paymentCount, subscriptionCount int64) AdminPlanPayload {
	return AdminPlanPayload{
		ID:                plan.ID,
		Name:              plan.Name,
		Description:       adminStringValue(plan.Description),
		Features:          adminStringSliceValue(plan.Features),
		Price:             plan.Price,
		Cycle:             plan.Cycle,
		StorageLimit:      plan.StorageLimit,
		UploadLimit:       plan.UploadLimit,
		DurationLimit:     plan.DurationLimit,
		QualityLimit:      plan.QualityLimit,
		IsActive:          adminBoolValue(plan.IsActive, true),
		UserCount:         userCount,
		PaymentCount:      paymentCount,
		SubscriptionCount: subscriptionCount,
	}
}

func (h *Handler) loadPlanUsageCounts(ctx *gin.Context, planID string) (int64, int64, int64, error) {
	var userCount int64
	if err := h.db.WithContext(ctx.Request.Context()).Model(&model.User{}).Where("plan_id = ?", planID).Count(&userCount).Error; err != nil {
		return 0, 0, 0, err
	}

	var paymentCount int64
	if err := h.db.WithContext(ctx.Request.Context()).Model(&model.Payment{}).Where("plan_id = ?", planID).Count(&paymentCount).Error; err != nil {
		return 0, 0, 0, err
	}

	var subscriptionCount int64
	if err := h.db.WithContext(ctx.Request.Context()).Model(&model.PlanSubscription{}).Where("plan_id = ?", planID).Count(&subscriptionCount).Error; err != nil {
		return 0, 0, 0, err
	}

	return userCount, paymentCount, subscriptionCount, nil
}

func validatePlanRequest(req *SavePlanRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "Name is required"
	}
	if strings.TrimSpace(req.Cycle) == "" {
		return "Cycle is required"
	}
	if req.Price < 0 {
		return "Price must be greater than or equal to 0"
	}
	if req.StorageLimit <= 0 {
		return "Storage limit must be greater than 0"
	}
	if req.UploadLimit <= 0 {
		return "Upload limit must be greater than 0"
	}
	return ""
}

// @Summary      List Plans
// @Description  Get all plans with usage counts (admin only)
// @Tags         admin
// @Produce      json
// @Success      200  {object}  response.Response
// @Router       /admin/plans [get]
// @Security     BearerAuth
func (h *Handler) ListPlans(c *gin.Context) {
	ctx := c.Request.Context()
	var plans []model.Plan
	if err := h.db.WithContext(ctx).Order("price ASC").Find(&plans).Error; err != nil {
		h.logger.Error("Failed to list plans", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list plans")
		return
	}

	result := make([]AdminPlanPayload, 0, len(plans))
	for _, plan := range plans {
		userCount, paymentCount, subscriptionCount, err := h.loadPlanUsageCounts(c, plan.ID)
		if err != nil {
			h.logger.Error("Failed to load plan usage", "error", err, "plan_id", plan.ID)
			response.Error(c, http.StatusInternalServerError, "Failed to list plans")
			return
		}
		result = append(result, buildAdminPlanPayload(plan, userCount, paymentCount, subscriptionCount))
	}

	response.Success(c, gin.H{"plans": result})
}

// @Summary      Create Plan
// @Description  Create a plan (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request body SavePlanRequest true "Plan payload"
// @Success      201  {object}  response.Response
// @Router       /admin/plans [post]
// @Security     BearerAuth
func (h *Handler) CreatePlan(c *gin.Context) {
	var req SavePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if msg := validatePlanRequest(&req); msg != "" {
		response.Error(c, http.StatusBadRequest, msg)
		return
	}

	plan := &model.Plan{
		ID:            uuid.New().String(),
		Name:          strings.TrimSpace(req.Name),
		Description:   adminStringPtr(req.Description),
		Features:      adminStringSlice(req.Features),
		Price:         req.Price,
		Cycle:         strings.TrimSpace(req.Cycle),
		StorageLimit:  req.StorageLimit,
		UploadLimit:   req.UploadLimit,
		DurationLimit: 0,
		QualityLimit:  "",
		IsActive: func() *bool {
			value := true
			if req.IsActive != nil {
				value = *req.IsActive
			}
			return &value
		}(),
	}

	if err := h.db.WithContext(c.Request.Context()).Create(plan).Error; err != nil {
		h.logger.Error("Failed to create plan", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create plan")
		return
	}

	response.Created(c, gin.H{"plan": buildAdminPlanPayload(*plan, 0, 0, 0)})
}

// @Summary      Update Plan
// @Description  Update a plan (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "Plan ID"
// @Param        request body SavePlanRequest true "Plan payload"
// @Success      200  {object}  response.Response
// @Router       /admin/plans/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdatePlan(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Plan not found")
		return
	}

	var req SavePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if msg := validatePlanRequest(&req); msg != "" {
		response.Error(c, http.StatusBadRequest, msg)
		return
	}

	ctx := c.Request.Context()
	var plan model.Plan
	if err := h.db.WithContext(ctx).Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Plan not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to update plan")
		return
	}

	plan.Name = strings.TrimSpace(req.Name)
	plan.Description = adminStringPtr(req.Description)
	plan.Features = adminStringSlice(req.Features)
	plan.Price = req.Price
	plan.Cycle = strings.TrimSpace(req.Cycle)
	plan.StorageLimit = req.StorageLimit
	plan.UploadLimit = req.UploadLimit
	if req.IsActive != nil {
		plan.IsActive = req.IsActive
	}

	if err := h.db.WithContext(ctx).Save(&plan).Error; err != nil {
		h.logger.Error("Failed to update plan", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update plan")
		return
	}

	userCount, paymentCount, subscriptionCount, err := h.loadPlanUsageCounts(c, plan.ID)
	if err != nil {
		h.logger.Error("Failed to load plan usage", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to update plan")
		return
	}

	response.Success(c, gin.H{"plan": buildAdminPlanPayload(plan, userCount, paymentCount, subscriptionCount)})
}

// @Summary      Delete Plan
// @Description  Delete a plan, or deactivate it if already used (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "Plan ID"
// @Success      200  {object}  response.Response
// @Router       /admin/plans/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeletePlan(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		response.Error(c, http.StatusNotFound, "Plan not found")
		return
	}

	ctx := c.Request.Context()
	var plan model.Plan
	if err := h.db.WithContext(ctx).Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusNotFound, "Plan not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to delete plan")
		return
	}

	var paymentCount int64
	if err := h.db.WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", id).Count(&paymentCount).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to delete plan")
		return
	}
	var subscriptionCount int64
	if err := h.db.WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", id).Count(&subscriptionCount).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to delete plan")
		return
	}

	if paymentCount > 0 || subscriptionCount > 0 {
		inactive := false
		if err := h.db.WithContext(ctx).Model(&model.Plan{}).Where("id = ?", id).Update("is_active", inactive).Error; err != nil {
			h.logger.Error("Failed to deactivate plan", "error", err)
			response.Error(c, http.StatusInternalServerError, "Failed to deactivate plan")
			return
		}
		response.Success(c, gin.H{"message": "Plan deactivated", "mode": "deactivated"})
		return
	}

	if err := h.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Plan{}).Error; err != nil {
		h.logger.Error("Failed to delete plan", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete plan")
		return
	}

	response.Success(c, gin.H{"message": "Plan deleted", "mode": "deleted"})
}
