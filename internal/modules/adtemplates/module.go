package adtemplates

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/modules/common"
)

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) ListAdTemplates(ctx context.Context, queryValue ListAdTemplatesQuery) (*ListAdTemplatesResult, error) {
	var items []model.AdTemplate
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", queryValue.UserID).Order("is_default DESC").Order("created_at DESC").Find(&items).Error; err != nil {
		m.runtime.Logger().Error("Failed to list ad templates", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load ad templates")
	}
	result := &ListAdTemplatesResult{Items: make([]AdTemplateView, 0, len(items))}
	for i := range items {
		result.Items = append(result.Items, AdTemplateView{Template: &items[i]})
	}
	return result, nil
}

func (m *Module) CreateAdTemplate(ctx context.Context, cmd CreateAdTemplateCommand) (*AdTemplateView, error) {
	name := strings.TrimSpace(cmd.Name)
	vastURL := strings.TrimSpace(cmd.VastTagURL)
	if name == "" || vastURL == "" {
		return nil, status.Error(codes.InvalidArgument, "Name and VAST URL are required")
	}
	format := common.NormalizeAdFormat(cmd.AdFormat)
	if format == "mid-roll" && (cmd.Duration == nil || *cmd.Duration <= 0) {
		return nil, status.Error(codes.InvalidArgument, "Duration is required for mid-roll templates")
	}
	item := &model.AdTemplate{
		ID:          uuid.New().String(),
		UserID:      cmd.UserID,
		Name:        name,
		Description: common.NullableTrimmedString(cmd.Description),
		VastTagURL:  vastURL,
		AdFormat:    model.StringPtr(format),
		Duration:    common.Int32PtrToInt64Ptr(cmd.Duration),
		IsActive:    model.BoolPtr(cmd.IsActive == nil || *cmd.IsActive),
		IsDefault:   cmd.IsDefault != nil && *cmd.IsDefault,
	}
	if !common.AdTemplateIsActive(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultTemplates(tx, cmd.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		m.runtime.Logger().Error("Failed to create ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &AdTemplateView{Template: item}, nil
}

func (m *Module) UpdateAdTemplate(ctx context.Context, cmd UpdateAdTemplateCommand) (*AdTemplateView, error) {
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}
	name := strings.TrimSpace(cmd.Name)
	vastURL := strings.TrimSpace(cmd.VastTagURL)
	if name == "" || vastURL == "" {
		return nil, status.Error(codes.InvalidArgument, "Name and VAST URL are required")
	}
	format := common.NormalizeAdFormat(cmd.AdFormat)
	if format == "mid-roll" && (cmd.Duration == nil || *cmd.Duration <= 0) {
		return nil, status.Error(codes.InvalidArgument, "Duration is required for mid-roll templates")
	}
	var item model.AdTemplate
	if err := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", cmd.ID, cmd.UserID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		m.runtime.Logger().Error("Failed to load ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	item.Name = name
	item.Description = common.NullableTrimmedString(cmd.Description)
	item.VastTagURL = vastURL
	item.AdFormat = model.StringPtr(format)
	item.Duration = common.Int32PtrToInt64Ptr(cmd.Duration)
	if cmd.IsActive != nil {
		item.IsActive = model.BoolPtr(*cmd.IsActive)
	}
	if cmd.IsDefault != nil {
		item.IsDefault = *cmd.IsDefault
	}
	if !common.AdTemplateIsActive(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultTemplates(tx, cmd.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		m.runtime.Logger().Error("Failed to update ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &AdTemplateView{Template: &item}, nil
}

func (m *Module) DeleteAdTemplate(ctx context.Context, cmd DeleteAdTemplateCommand) error {
	if cmd.ID == "" {
		return status.Error(codes.NotFound, "Ad template not found")
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Video{}).Where("user_id = ? AND ad_id = ?", cmd.UserID, cmd.ID).Update("ad_id", nil).Error; err != nil {
			return err
		}
		res := tx.Where("id = ? AND user_id = ?", cmd.ID, cmd.UserID).Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.NotFound, "Ad template not found")
		}
		m.runtime.Logger().Error("Failed to delete ad template", "error", err)
		return status.Error(codes.Internal, "Failed to delete ad template")
	}
	return nil
}

func (m *Module) ListAdminAdTemplates(ctx context.Context, queryValue ListAdminAdTemplatesQuery) (*ListAdminAdTemplatesResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)
	limitInt := int(limit)
	search := strings.TrimSpace(common.ProtoStringValue(queryValue.Search))
	userID := strings.TrimSpace(common.ProtoStringValue(queryValue.UserID))
	db := m.runtime.DB().WithContext(ctx).Model(&model.AdTemplate{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("name ILIKE ?", like)
	}
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list ad templates")
	}
	var templates []model.AdTemplate
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&templates).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list ad templates")
	}
	items := make([]AdminAdTemplateView, 0, len(templates))
	for i := range templates {
		view, err := m.buildAdminAdTemplate(ctx, &templates[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list ad templates")
		}
		items = append(items, view)
	}
	return &ListAdminAdTemplatesResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetAdminAdTemplate(ctx context.Context, queryValue GetAdminAdTemplateQuery) (*AdminAdTemplateView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if queryValue.ID == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}
	var item model.AdTemplate
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", queryValue.ID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load ad template")
	}
	payload, err := m.buildAdminAdTemplate(ctx, &item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load ad template")
	}
	return &payload, nil
}

func (m *Module) CreateAdminAdTemplate(ctx context.Context, cmd CreateAdminAdTemplateCommand) (*AdminAdTemplateView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if msg := validateAdminAdTemplateInput(cmd.UserID, cmd.Name, cmd.VastTagURL, cmd.AdFormat, cmd.Duration); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", strings.TrimSpace(cmd.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	item := &model.AdTemplate{ID: uuid.New().String(), UserID: user.ID, Name: strings.TrimSpace(cmd.Name), Description: common.NullableTrimmedStringPtr(cmd.Description), VastTagURL: strings.TrimSpace(cmd.VastTagURL), AdFormat: model.StringPtr(common.NormalizeAdFormat(cmd.AdFormat)), Duration: cmd.Duration, IsActive: model.BoolPtr(cmd.IsActive), IsDefault: cmd.IsDefault}
	if !common.BoolValue(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultTemplates(tx, item.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	payload, err := m.buildAdminAdTemplate(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &payload, nil
}

func (m *Module) UpdateAdminAdTemplate(ctx context.Context, cmd UpdateAdminAdTemplateCommand) (*AdminAdTemplateView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}
	if msg := validateAdminAdTemplateInput(cmd.UserID, cmd.Name, cmd.VastTagURL, cmd.AdFormat, cmd.Duration); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", strings.TrimSpace(cmd.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	var item model.AdTemplate
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	item.UserID = user.ID
	item.Name = strings.TrimSpace(cmd.Name)
	item.Description = common.NullableTrimmedStringPtr(cmd.Description)
	item.VastTagURL = strings.TrimSpace(cmd.VastTagURL)
	item.AdFormat = model.StringPtr(common.NormalizeAdFormat(cmd.AdFormat))
	item.Duration = cmd.Duration
	item.IsActive = model.BoolPtr(cmd.IsActive)
	item.IsDefault = cmd.IsDefault
	if !common.BoolValue(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultTemplates(tx, item.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	payload, err := m.buildAdminAdTemplate(ctx, &item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &payload, nil
}

func (m *Module) DeleteAdminAdTemplate(ctx context.Context, cmd DeleteAdminAdTemplateCommand) error {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return err
	}
	if cmd.ID == "" {
		return status.Error(codes.NotFound, "Ad template not found")
	}
	err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Video{}).Where("ad_id = ?", cmd.ID).Update("ad_id", nil).Error; err != nil {
			return err
		}
		res := tx.Where("id = ?", cmd.ID).Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.NotFound, "Ad template not found")
		}
		return status.Error(codes.Internal, "Failed to delete ad template")
	}
	return nil
}

func (m *Module) buildAdminAdTemplate(ctx context.Context, item *model.AdTemplate) (AdminAdTemplateView, error) {
	if item == nil {
		return AdminAdTemplateView{}, nil
	}
	var createdAt *string
	if item.CreatedAt != nil {
		formatted := item.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	updated := item.UpdatedAt.UTC().Format(time.RFC3339)
	updatedAt := &updated
	ownerEmail, err := m.loadAdminUserEmail(ctx, item.UserID)
	if err != nil {
		return AdminAdTemplateView{}, err
	}
	return AdminAdTemplateView{ID: item.ID, UserID: item.UserID, Name: item.Name, Description: common.NullableTrimmedString(item.Description), VastTagURL: item.VastTagURL, AdFormat: common.StringValue(item.AdFormat), Duration: item.Duration, IsActive: common.BoolValue(item.IsActive), IsDefault: item.IsDefault, OwnerEmail: ownerEmail, CreatedAt: createdAt, UpdatedAt: updatedAt}, nil
}

func (m *Module) loadAdminUserEmail(ctx context.Context, userID string) (*string, error) {
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Select("id, email").Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return common.NullableTrimmedString(&user.Email), nil
}

func validateAdminAdTemplateInput(userID, name, vastTagURL, adFormat string, duration *int64) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(vastTagURL) == "" {
		return "Name and VAST URL are required"
	}
	format := common.NormalizeAdFormat(adFormat)
	if format == "mid-roll" && (duration == nil || *duration <= 0) {
		return "Duration is required for mid-roll templates"
	}
	return ""
}
