package playerconfigs

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

func (m *Module) ListPlayerConfigs(ctx context.Context, queryValue ListPlayerConfigsQuery) (*ListPlayerConfigsResult, error) {
	var items []model.PlayerConfig
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", queryValue.UserID).Order("is_default DESC").Order("created_at DESC").Find(&items).Error; err != nil {
		m.runtime.Logger().Error("Failed to list player configs", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load player configs")
	}
	result := &ListPlayerConfigsResult{Items: make([]PlayerConfigView, 0, len(items))}
	for i := range items {
		result.Items = append(result.Items, PlayerConfigView{Config: &items[i]})
	}
	return result, nil
}

func (m *Module) CreatePlayerConfig(ctx context.Context, cmd CreatePlayerConfigCommand) (*PlayerConfigView, error) {
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name is required")
	}
	item := &model.PlayerConfig{ID: uuid.New().String(), UserID: cmd.UserID, Name: name, Description: common.NullableTrimmedString(cmd.Description), Autoplay: cmd.Autoplay, Loop: cmd.Loop, Muted: cmd.Muted, ShowControls: model.BoolPtr(cmd.ShowControls), Pip: model.BoolPtr(cmd.Pip), Airplay: model.BoolPtr(cmd.Airplay), Chromecast: model.BoolPtr(cmd.Chromecast), IsActive: model.BoolPtr(cmd.IsActive == nil || *cmd.IsActive), IsDefault: cmd.IsDefault != nil && *cmd.IsDefault, EncrytionM3u8: model.BoolPtr(cmd.EncrytionM3U8 == nil || *cmd.EncrytionM3U8), LogoURL: common.NullableTrimmedString(cmd.LogoURL)}
	if !common.PlayerConfigIsActive(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := common.LockUserForUpdate(ctx, tx, cmd.UserID)
		if err != nil {
			return err
		}
		var configCount int64
		if err := tx.WithContext(ctx).Model(&model.PlayerConfig{}).Where("user_id = ?", cmd.UserID).Count(&configCount).Error; err != nil {
			return err
		}
		if err := common.PlayerConfigActionAllowed(lockedUser, configCount, "create"); err != nil {
			return err
		}
		if item.IsDefault {
			if err := common.UnsetDefaultPlayerConfigs(tx, cmd.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		m.runtime.Logger().Error("Failed to create player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &PlayerConfigView{Config: item}, nil
}

func (m *Module) UpdatePlayerConfig(ctx context.Context, cmd UpdatePlayerConfigCommand) (*PlayerConfigView, error) {
	if strings.TrimSpace(cmd.ID) == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name is required")
	}
	var item model.PlayerConfig
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := common.LockUserForUpdate(ctx, tx, cmd.UserID)
		if err != nil {
			return err
		}
		var configCount int64
		if err := tx.WithContext(ctx).Model(&model.PlayerConfig{}).Where("user_id = ?", cmd.UserID).Count(&configCount).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Where("id = ? AND user_id = ?", cmd.ID, cmd.UserID).First(&item).Error; err != nil {
			return err
		}
		action := "update"
		wasActive := common.PlayerConfigIsActive(item.IsActive)
		if cmd.IsActive != nil && *cmd.IsActive != wasActive {
			action = "toggle-active"
		}
		if cmd.IsDefault != nil && *cmd.IsDefault {
			action = "set-default"
		}
		if err := common.PlayerConfigActionAllowed(lockedUser, configCount, action); err != nil {
			return err
		}
		item.Name = name
		item.Description = common.NullableTrimmedString(cmd.Description)
		item.Autoplay = cmd.Autoplay
		item.Loop = cmd.Loop
		item.Muted = cmd.Muted
		item.ShowControls = model.BoolPtr(cmd.ShowControls)
		item.Pip = model.BoolPtr(cmd.Pip)
		item.Airplay = model.BoolPtr(cmd.Airplay)
		item.Chromecast = model.BoolPtr(cmd.Chromecast)
		if cmd.EncrytionM3U8 != nil {
			item.EncrytionM3u8 = model.BoolPtr(*cmd.EncrytionM3U8)
		}
		if cmd.LogoURL != nil {
			item.LogoURL = common.NullableTrimmedString(cmd.LogoURL)
		}
		if cmd.IsActive != nil {
			item.IsActive = model.BoolPtr(*cmd.IsActive)
		}
		if cmd.IsDefault != nil {
			item.IsDefault = *cmd.IsDefault
		}
		if !common.PlayerConfigIsActive(item.IsActive) {
			item.IsDefault = false
		}
		if item.IsDefault {
			if err := common.UnsetDefaultPlayerConfigs(tx, cmd.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		m.runtime.Logger().Error("Failed to update player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &PlayerConfigView{Config: &item}, nil
}

func (m *Module) DeletePlayerConfig(ctx context.Context, cmd DeletePlayerConfigCommand) error {
	if strings.TrimSpace(cmd.ID) == "" {
		return status.Error(codes.NotFound, "Player config not found")
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := common.LockUserForUpdate(ctx, tx, cmd.UserID)
		if err != nil {
			return err
		}
		var configCount int64
		if err := tx.WithContext(ctx).Model(&model.PlayerConfig{}).Where("user_id = ?", cmd.UserID).Count(&configCount).Error; err != nil {
			return err
		}
		if err := common.PlayerConfigActionAllowed(lockedUser, configCount, "delete"); err != nil {
			return err
		}
		res := tx.Where("id = ? AND user_id = ?", cmd.ID, cmd.UserID).Delete(&model.PlayerConfig{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.NotFound, "Player config not found")
		}
		if status.Code(err) != codes.Unknown {
			return err
		}
		m.runtime.Logger().Error("Failed to delete player config", "error", err)
		return status.Error(codes.Internal, "Failed to delete player config")
	}
	return nil
}

func (m *Module) ListAdminPlayerConfigs(ctx context.Context, queryValue ListAdminPlayerConfigsQuery) (*ListAdminPlayerConfigsResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)
	limitInt := int(limit)
	search := strings.TrimSpace(common.ProtoStringValue(queryValue.Search))
	userID := strings.TrimSpace(common.ProtoStringValue(queryValue.UserID))
	db := m.runtime.DB().WithContext(ctx).Model(&model.PlayerConfig{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("name ILIKE ?", like)
	}
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list player configs")
	}
	var configs []model.PlayerConfig
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&configs).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list player configs")
	}
	items := make([]AdminPlayerConfigView, 0, len(configs))
	for i := range configs {
		payload, err := m.buildAdminPlayerConfig(ctx, &configs[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list player configs")
		}
		items = append(items, payload)
	}
	return &ListAdminPlayerConfigsResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetAdminPlayerConfig(ctx context.Context, queryValue GetAdminPlayerConfigQuery) (*AdminPlayerConfigView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(queryValue.ID) == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}
	var item model.PlayerConfig
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", queryValue.ID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load player config")
	}
	payload, err := m.buildAdminPlayerConfig(ctx, &item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load player config")
	}
	return &payload, nil
}

func (m *Module) CreateAdminPlayerConfig(ctx context.Context, cmd CreateAdminPlayerConfigCommand) (*AdminPlayerConfigView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if msg := validateAdminPlayerConfigInput(cmd.UserID, cmd.Name); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", strings.TrimSpace(cmd.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	item := &model.PlayerConfig{ID: uuid.New().String(), UserID: user.ID, Name: strings.TrimSpace(cmd.Name), Description: common.NullableTrimmedStringPtr(cmd.Description), Autoplay: cmd.Autoplay, Loop: cmd.Loop, Muted: cmd.Muted, ShowControls: model.BoolPtr(cmd.ShowControls), Pip: model.BoolPtr(cmd.Pip), Airplay: model.BoolPtr(cmd.Airplay), Chromecast: model.BoolPtr(cmd.Chromecast), IsActive: model.BoolPtr(cmd.IsActive), IsDefault: cmd.IsDefault, EncrytionM3u8: model.BoolPtr(cmd.EncrytionM3U8 == nil || *cmd.EncrytionM3U8), LogoURL: common.NullableTrimmedStringPtr(cmd.LogoURL)}
	if !common.BoolValue(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultPlayerConfigs(tx, item.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	payload, err := m.buildAdminPlayerConfig(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &payload, nil
}

func (m *Module) UpdateAdminPlayerConfig(ctx context.Context, cmd UpdateAdminPlayerConfigCommand) (*AdminPlayerConfigView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cmd.ID) == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}
	if msg := validateAdminPlayerConfigInput(cmd.UserID, cmd.Name); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", strings.TrimSpace(cmd.UserID)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	var item model.PlayerConfig
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	item.UserID = user.ID
	item.Name = strings.TrimSpace(cmd.Name)
	item.Description = common.NullableTrimmedStringPtr(cmd.Description)
	item.Autoplay = cmd.Autoplay
	item.Loop = cmd.Loop
	item.Muted = cmd.Muted
	item.ShowControls = model.BoolPtr(cmd.ShowControls)
	item.Pip = model.BoolPtr(cmd.Pip)
	item.Airplay = model.BoolPtr(cmd.Airplay)
	item.Chromecast = model.BoolPtr(cmd.Chromecast)
	item.IsActive = model.BoolPtr(cmd.IsActive)
	item.IsDefault = cmd.IsDefault
	if cmd.EncrytionM3U8 != nil {
		item.EncrytionM3u8 = model.BoolPtr(*cmd.EncrytionM3U8)
	}
	if cmd.LogoURL != nil {
		item.LogoURL = common.NullableTrimmedStringPtr(cmd.LogoURL)
	}
	if !common.BoolValue(item.IsActive) {
		item.IsDefault = false
	}
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := common.UnsetDefaultPlayerConfigs(tx, item.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	payload, err := m.buildAdminPlayerConfig(ctx, &item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &payload, nil
}

func (m *Module) DeleteAdminPlayerConfig(ctx context.Context, cmd DeleteAdminPlayerConfigCommand) error {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(cmd.ID) == "" {
		return status.Error(codes.NotFound, "Player config not found")
	}
	res := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).Delete(&model.PlayerConfig{})
	if res.Error != nil {
		return status.Error(codes.Internal, "Failed to delete player config")
	}
	if res.RowsAffected == 0 {
		return status.Error(codes.NotFound, "Player config not found")
	}
	return nil
}

func (m *Module) buildAdminPlayerConfig(ctx context.Context, item *model.PlayerConfig) (AdminPlayerConfigView, error) {
	if item == nil {
		return AdminPlayerConfigView{}, nil
	}
	ownerEmail, err := m.loadAdminUserEmail(ctx, item.UserID)
	if err != nil {
		return AdminPlayerConfigView{}, err
	}
	var createdAt *string
	if item.CreatedAt != nil {
		formatted := item.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	updated := item.UpdatedAt.UTC().Format(time.RFC3339)
	updatedAt := &updated
	return AdminPlayerConfigView{ID: item.ID, UserID: item.UserID, Name: item.Name, Description: item.Description, Autoplay: item.Autoplay, Loop: item.Loop, Muted: item.Muted, ShowControls: common.BoolValue(item.ShowControls), Pip: common.BoolValue(item.Pip), Airplay: common.BoolValue(item.Airplay), Chromecast: common.BoolValue(item.Chromecast), IsActive: common.BoolValue(item.IsActive), IsDefault: item.IsDefault, OwnerEmail: ownerEmail, CreatedAt: createdAt, UpdatedAt: updatedAt, EncrytionM3U8: common.BoolValue(item.EncrytionM3u8), LogoURL: common.NullableTrimmedString(item.LogoURL)}, nil
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

func validateAdminPlayerConfigInput(userID, name string) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(name) == "" {
		return "Name is required"
	}
	return ""
}
