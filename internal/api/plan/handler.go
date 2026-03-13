//go:build ignore
// +build ignore

package plan

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	cfg    *config.Config
	db     *gorm.DB
}

func NewHandler(l logger.Logger, cfg *config.Config, db *gorm.DB) PlanHandler {
	return &Handler{
		logger: l,
		cfg:    cfg,
		db:     db,
	}
}

// @Summary      List Plans
// @Description  Get all active plans
// @Tags         plan
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /plans [get]
// @Security     BearerAuth
func (h *Handler) ListPlans(c *gin.Context) {
	var plans []model.Plan
	if err := h.db.WithContext(c.Request.Context()).Where("is_active = ?", true).Find(&plans).Error; err != nil {
		h.logger.Error("Failed to fetch plans", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch plans")
		return
	}

	response.Success(c, gin.H{"plans": plans})
}
