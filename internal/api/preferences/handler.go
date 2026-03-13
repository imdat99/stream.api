//go:build ignore
// +build ignore

package preferences

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
)

type Handler struct {
	logger logger.Logger
	db     *gorm.DB
}

type SettingsPreferencesRequest struct {
	EmailNotifications     *bool   `json:"email_notifications"`
	PushNotifications      *bool   `json:"push_notifications"`
	MarketingNotifications *bool   `json:"marketing_notifications"`
	TelegramNotifications  *bool   `json:"telegram_notifications"`
	Autoplay               *bool   `json:"autoplay"`
	Loop                   *bool   `json:"loop"`
	Muted                  *bool   `json:"muted"`
	ShowControls           *bool   `json:"show_controls"`
	Pip                    *bool   `json:"pip"`
	Airplay                *bool   `json:"airplay"`
	Chromecast             *bool   `json:"chromecast"`
	Language               *string `json:"language"`
	Locale                 *string `json:"locale"`
}

func NewHandler(l logger.Logger, db *gorm.DB) *Handler {
	return &Handler{logger: l, db: db}
}

// @Summary      Get Preferences
// @Description  Get notification, player, and locale preferences for the current user
// @Tags         settings
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /settings/preferences [get]
// @Security     BearerAuth
func (h *Handler) GetPreferences(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	pref, err := LoadUserPreferences(c.Request.Context(), h.db, userID)
	if err != nil {
		h.logger.Error("Failed to load preferences", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to load preferences")
		return
	}

	response.Success(c, gin.H{"preferences": pref})
}

// @Summary      Update Preferences
// @Description  Update notification, player, and locale preferences for the current user
// @Tags         settings
// @Accept       json
// @Produce      json
// @Param        request body SettingsPreferencesRequest true "Preferences payload"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /settings/preferences [put]
// @Security     BearerAuth
func (h *Handler) UpdatePreferences(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req SettingsPreferencesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	pref, err := UpdateUserPreferences(c.Request.Context(), h.db, h.logger, userID, UpdateInput{
		EmailNotifications:     req.EmailNotifications,
		PushNotifications:      req.PushNotifications,
		MarketingNotifications: req.MarketingNotifications,
		TelegramNotifications:  req.TelegramNotifications,
		Autoplay:               req.Autoplay,
		Loop:                   req.Loop,
		Muted:                  req.Muted,
		ShowControls:           req.ShowControls,
		Pip:                    req.Pip,
		Airplay:                req.Airplay,
		Chromecast:             req.Chromecast,
		Language:               req.Language,
		Locale:                 req.Locale,
	})
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to save preferences")
		return
	}

	response.Success(c, gin.H{"preferences": pref})
}
