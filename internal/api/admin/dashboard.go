//go:build ignore
// +build ignore

package admin

import (
	"time"

	"github.com/gin-gonic/gin"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

type DashboardPayload struct {
	TotalUsers          int64   `json:"total_users"`
	TotalVideos         int64   `json:"total_videos"`
	TotalStorageUsed    int64   `json:"total_storage_used"`
	TotalPayments       int64   `json:"total_payments"`
	TotalRevenue        float64 `json:"total_revenue"`
	ActiveSubscriptions int64   `json:"active_subscriptions"`
	TotalAdTemplates    int64   `json:"total_ad_templates"`
	NewUsersToday       int64   `json:"new_users_today"`
	NewVideosToday      int64   `json:"new_videos_today"`
}

// @Summary      Admin Dashboard
// @Description  Get system-wide statistics for the admin dashboard
// @Tags         admin
// @Produce      json
// @Success      200  {object}  response.Response{data=DashboardPayload}
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Router       /admin/dashboard [get]
// @Security     BearerAuth
func (h *Handler) Dashboard(c *gin.Context) {
	ctx := c.Request.Context()
	var payload DashboardPayload

	h.db.WithContext(ctx).Model(&model.User{}).Count(&payload.TotalUsers)
	h.db.WithContext(ctx).Model(&model.Video{}).Count(&payload.TotalVideos)

	h.db.WithContext(ctx).Model(&model.User{}).
		Select("COALESCE(SUM(storage_used), 0)").
		Row().Scan(&payload.TotalStorageUsed)

	h.db.WithContext(ctx).Model(&model.Payment{}).Count(&payload.TotalPayments)

	h.db.WithContext(ctx).Model(&model.Payment{}).
		Where("status = ?", "SUCCESS").
		Select("COALESCE(SUM(amount), 0)").
		Row().Scan(&payload.TotalRevenue)

	h.db.WithContext(ctx).Model(&model.PlanSubscription{}).
		Where("expires_at > ?", time.Now()).
		Count(&payload.ActiveSubscriptions)

	h.db.WithContext(ctx).Model(&model.AdTemplate{}).Count(&payload.TotalAdTemplates)

	today := time.Now().Truncate(24 * time.Hour)
	h.db.WithContext(ctx).Model(&model.User{}).
		Where("created_at >= ?", today).
		Count(&payload.NewUsersToday)
	h.db.WithContext(ctx).Model(&model.Video{}).
		Where("created_at >= ?", today).
		Count(&payload.NewVideosToday)

	response.Success(c, payload)
}
