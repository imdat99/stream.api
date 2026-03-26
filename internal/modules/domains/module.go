package domains

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"stream.api/internal/database/model"
	"stream.api/internal/modules/common"
)

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) ListDomains(ctx context.Context, queryValue ListDomainsQuery) (*ListDomainsResult, error) {
	var rows []model.Domain
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", queryValue.UserID).Order("created_at DESC").Find(&rows).Error; err != nil {
		m.runtime.Logger().Error("Failed to list domains", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load domains")
	}
	items := make([]DomainView, 0, len(rows))
	for i := range rows {
		items = append(items, DomainView{Domain: &rows[i]})
	}
	return &ListDomainsResult{Items: items}, nil
}

func (m *Module) CreateDomain(ctx context.Context, cmd CreateDomainCommand) (*DomainView, error) {
	name := common.NormalizeDomain(cmd.Name)
	if name == "" || !strings.Contains(name, ".") || strings.ContainsAny(name, "/ ") {
		return nil, status.Error(codes.InvalidArgument, "Invalid domain")
	}
	var count int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Domain{}).Where("user_id = ? AND name = ?", cmd.UserID, name).Count(&count).Error; err != nil {
		m.runtime.Logger().Error("Failed to validate domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create domain")
	}
	if count > 0 {
		return nil, status.Error(codes.InvalidArgument, "Domain already exists")
	}
	item := &model.Domain{ID: uuid.New().String(), UserID: cmd.UserID, Name: name}
	if err := m.runtime.DB().WithContext(ctx).Create(item).Error; err != nil {
		m.runtime.Logger().Error("Failed to create domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create domain")
	}
	return &DomainView{Domain: item}, nil
}

func (m *Module) DeleteDomain(ctx context.Context, cmd DeleteDomainCommand) error {
	if cmd.ID == "" {
		return status.Error(codes.NotFound, "Domain not found")
	}
	res := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", cmd.ID, cmd.UserID).Delete(&model.Domain{})
	if res.Error != nil {
		m.runtime.Logger().Error("Failed to delete domain", "error", res.Error)
		return status.Error(codes.Internal, "Failed to delete domain")
	}
	if res.RowsAffected == 0 {
		return status.Error(codes.NotFound, "Domain not found")
	}
	return nil
}
