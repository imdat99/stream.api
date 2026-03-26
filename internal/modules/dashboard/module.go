package dashboard

import (
	"context"
	"time"

	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) GetAdminDashboard(ctx context.Context, _ *appv1.GetAdminDashboardRequest) (*appv1.GetAdminDashboardResponse, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	dashboard := &appv1.AdminDashboard{}
	db := m.runtime.DB().WithContext(ctx)
	db.Model(&model.User{}).Count(&dashboard.TotalUsers)
	db.Model(&model.Video{}).Count(&dashboard.TotalVideos)
	db.Model(&model.User{}).Select("COALESCE(SUM(storage_used), 0)").Row().Scan(&dashboard.TotalStorageUsed)
	db.Model(&model.Payment{}).Count(&dashboard.TotalPayments)
	db.Model(&model.Payment{}).Where("status = ?", "SUCCESS").Select("COALESCE(SUM(amount), 0)").Row().Scan(&dashboard.TotalRevenue)
	db.Model(&model.PlanSubscription{}).Where("expires_at > ?", time.Now()).Count(&dashboard.ActiveSubscriptions)
	db.Model(&model.AdTemplate{}).Count(&dashboard.TotalAdTemplates)
	today := time.Now().Truncate(24 * time.Hour)
	db.Model(&model.User{}).Where("created_at >= ?", today).Count(&dashboard.NewUsersToday)
	db.Model(&model.Video{}).Where("created_at >= ?", today).Count(&dashboard.NewVideosToday)
	return &appv1.GetAdminDashboardResponse{Dashboard: dashboard}, nil
}
