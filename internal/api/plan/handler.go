package plan

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"stream.api/internal/config"
	"stream.api/internal/database/query"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	cfg    *config.Config
}

func NewHandler(l logger.Logger, cfg *config.Config) PlanHandler {
	return &Handler{
		logger: l,
		cfg:    cfg,
	}
}

// @Summary      List Plans
// @Description  Get all active plans
// @Tags         plan
// @Produce      json
// @Success      200  {object}  response.Response{data=[]model.Plan}
// @Failure      500  {object}  response.Response
// @Router       /plans [get]
// @Security     BearerAuth
func (h *Handler) ListPlans(c *gin.Context) {
	p := query.Plan
	plans, err := p.WithContext(c.Request.Context()).Where(p.IsActive.Is(true)).Find()
	if err != nil {
		h.logger.Error("Failed to fetch plans", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to fetch plans")
		return
	}

	response.Success(c, gin.H{"plans": plans})
}
