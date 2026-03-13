//go:build ignore
// +build ignore

package usage

import (
	"net/http"

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

func NewHandler(l logger.Logger, db *gorm.DB) UsageHandler {
	return &Handler{
		logger: l,
		db:     db,
	}
}

// @Summary      Get Usage
// @Description  Get the authenticated user's total video count and total storage usage
// @Tags         usage
// @Produce      json
// @Success      200  {object}  response.Response{data=UsagePayload}
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /usage [get]
// @Security     BearerAuth
func (h *Handler) GetUsage(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, ok := c.Get("user")
	if !ok {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	currentUser, ok := user.(*model.User)
	if !ok || currentUser == nil || currentUser.ID != userID {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	payload, err := LoadUsage(c.Request.Context(), h.db, h.logger, currentUser)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to load usage")
		return
	}

	response.Success(c, payload)
}
