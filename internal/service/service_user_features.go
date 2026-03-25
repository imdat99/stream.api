package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func (s *appServices) ListNotifications(ctx context.Context, _ *appv1.ListNotificationsRequest) (*appv1.ListNotificationsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	var rows []model.Notification
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", result.UserID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		s.logger.Error("Failed to list notifications", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load notifications")
	}

	items := make([]*appv1.Notification, 0, len(rows))
	for _, row := range rows {
		items = append(items, toProtoNotification(row))
	}

	return &appv1.ListNotificationsResponse{Notifications: items}, nil
}
func (s *appServices) MarkNotificationRead(ctx context.Context, req *appv1.MarkNotificationReadRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	res := s.db.WithContext(ctx).
		Model(&model.Notification{}).
		Where("id = ? AND user_id = ?", id, result.UserID).
		Update("is_read", true)
	if res.Error != nil {
		s.logger.Error("Failed to update notification", "error", res.Error)
		return nil, status.Error(codes.Internal, "Failed to update notification")
	}
	if res.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	return messageResponse("Notification updated"), nil
}
func (s *appServices) MarkAllNotificationsRead(ctx context.Context, _ *appv1.MarkAllNotificationsReadRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.db.WithContext(ctx).
		Model(&model.Notification{}).
		Where("user_id = ? AND is_read = ?", result.UserID, false).
		Update("is_read", true).Error; err != nil {
		s.logger.Error("Failed to mark all notifications as read", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update notifications")
	}

	return messageResponse("All notifications marked as read"), nil
}
func (s *appServices) DeleteNotification(ctx context.Context, req *appv1.DeleteNotificationRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	res := s.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", id, result.UserID).
		Delete(&model.Notification{})
	if res.Error != nil {
		s.logger.Error("Failed to delete notification", "error", res.Error)
		return nil, status.Error(codes.Internal, "Failed to delete notification")
	}
	if res.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	return messageResponse("Notification deleted"), nil
}
func (s *appServices) ClearNotifications(ctx context.Context, _ *appv1.ClearNotificationsRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.db.WithContext(ctx).Where("user_id = ?", result.UserID).Delete(&model.Notification{}).Error; err != nil {
		s.logger.Error("Failed to clear notifications", "error", err)
		return nil, status.Error(codes.Internal, "Failed to clear notifications")
	}

	return messageResponse("All notifications deleted"), nil
}
func (s *appServices) ListDomains(ctx context.Context, _ *appv1.ListDomainsRequest) (*appv1.ListDomainsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	var rows []model.Domain
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", result.UserID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		s.logger.Error("Failed to list domains", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load domains")
	}

	items := make([]*appv1.Domain, 0, len(rows))
	for _, row := range rows {
		item := row
		items = append(items, toProtoDomain(&item))
	}

	return &appv1.ListDomainsResponse{Domains: items}, nil
}
func (s *appServices) CreateDomain(ctx context.Context, req *appv1.CreateDomainRequest) (*appv1.CreateDomainResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	name := normalizeDomain(req.GetName())
	if name == "" || !strings.Contains(name, ".") || strings.ContainsAny(name, "/ ") {
		return nil, status.Error(codes.InvalidArgument, "Invalid domain")
	}

	var count int64
	if err := s.db.WithContext(ctx).
		Model(&model.Domain{}).
		Where("user_id = ? AND name = ?", result.UserID, name).
		Count(&count).Error; err != nil {
		s.logger.Error("Failed to validate domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create domain")
	}
	if count > 0 {
		return nil, status.Error(codes.InvalidArgument, "Domain already exists")
	}

	item := &model.Domain{
		ID:     uuid.New().String(),
		UserID: result.UserID,
		Name:   name,
	}
	if err := s.db.WithContext(ctx).Create(item).Error; err != nil {
		s.logger.Error("Failed to create domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create domain")
	}

	return &appv1.CreateDomainResponse{Domain: toProtoDomain(item)}, nil
}
func (s *appServices) DeleteDomain(ctx context.Context, req *appv1.DeleteDomainRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Domain not found")
	}

	res := s.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", id, result.UserID).
		Delete(&model.Domain{})
	if res.Error != nil {
		s.logger.Error("Failed to delete domain", "error", res.Error)
		return nil, status.Error(codes.Internal, "Failed to delete domain")
	}
	if res.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Domain not found")
	}

	return messageResponse("Domain deleted"), nil
}
func (s *appServices) ListAdTemplates(ctx context.Context, _ *appv1.ListAdTemplatesRequest) (*appv1.ListAdTemplatesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	var items []model.AdTemplate
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", result.UserID).
		Order("is_default DESC").
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		s.logger.Error("Failed to list ad templates", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load ad templates")
	}

	payload := make([]*appv1.AdTemplate, 0, len(items))
	for _, item := range items {
		copyItem := item
		payload = append(payload, toProtoAdTemplate(&copyItem))
	}

	return &appv1.ListAdTemplatesResponse{Templates: payload}, nil
}
func (s *appServices) CreateAdTemplate(ctx context.Context, req *appv1.CreateAdTemplateRequest) (*appv1.CreateAdTemplateResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensurePaidPlan(result.User); err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.GetName())
	vastURL := strings.TrimSpace(req.GetVastTagUrl())
	if name == "" || vastURL == "" {
		return nil, status.Error(codes.InvalidArgument, "Name and VAST URL are required")
	}

	format := normalizeAdFormat(req.GetAdFormat())
	if format == "mid-roll" && (req.Duration == nil || *req.Duration <= 0) {
		return nil, status.Error(codes.InvalidArgument, "Duration is required for mid-roll templates")
	}

	item := &model.AdTemplate{
		ID:          uuid.New().String(),
		UserID:      result.UserID,
		Name:        name,
		Description: nullableTrimmedString(req.Description),
		VastTagURL:  vastURL,
		AdFormat:    model.StringPtr(format),
		Duration:    int32PtrToInt64Ptr(req.Duration),
		IsActive:    model.BoolPtr(req.IsActive == nil || *req.IsActive),
		IsDefault:   req.IsDefault != nil && *req.IsDefault,
	}
	if !adTemplateIsActive(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := unsetDefaultTemplates(tx, result.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		s.logger.Error("Failed to create ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	return &appv1.CreateAdTemplateResponse{Template: toProtoAdTemplate(item)}, nil
}
func (s *appServices) UpdateAdTemplate(ctx context.Context, req *appv1.UpdateAdTemplateRequest) (*appv1.UpdateAdTemplateResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensurePaidPlan(result.User); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}

	name := strings.TrimSpace(req.GetName())
	vastURL := strings.TrimSpace(req.GetVastTagUrl())
	if name == "" || vastURL == "" {
		return nil, status.Error(codes.InvalidArgument, "Name and VAST URL are required")
	}

	format := normalizeAdFormat(req.GetAdFormat())
	if format == "mid-roll" && (req.Duration == nil || *req.Duration <= 0) {
		return nil, status.Error(codes.InvalidArgument, "Duration is required for mid-roll templates")
	}

	var item model.AdTemplate
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, result.UserID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		s.logger.Error("Failed to load ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	item.Name = name
	item.Description = nullableTrimmedString(req.Description)
	item.VastTagURL = vastURL
	item.AdFormat = model.StringPtr(format)
	item.Duration = int32PtrToInt64Ptr(req.Duration)
	if req.IsActive != nil {
		item.IsActive = model.BoolPtr(*req.IsActive)
	}
	if req.IsDefault != nil {
		item.IsDefault = *req.IsDefault
	}
	if !adTemplateIsActive(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := unsetDefaultTemplates(tx, result.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		s.logger.Error("Failed to update ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	return &appv1.UpdateAdTemplateResponse{Template: toProtoAdTemplate(&item)}, nil
}
func (s *appServices) DeleteAdTemplate(ctx context.Context, req *appv1.DeleteAdTemplateRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensurePaidPlan(result.User); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Video{}).
			Where("user_id = ? AND ad_id = ?", result.UserID, id).
			Update("ad_id", nil).Error; err != nil {
			return err
		}

		res := tx.Where("id = ? AND user_id = ?", id, result.UserID).Delete(&model.AdTemplate{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		s.logger.Error("Failed to delete ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete ad template")
	}

	return messageResponse("Ad template deleted"), nil
}
func (s *appServices) ListPlans(ctx context.Context, _ *appv1.ListPlansRequest) (*appv1.ListPlansResponse, error) {
	if _, err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	var plans []model.Plan
	if err := s.db.WithContext(ctx).Where("is_active = ?", true).Find(&plans).Error; err != nil {
		s.logger.Error("Failed to fetch plans", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch plans")
	}

	items := make([]*appv1.Plan, 0, len(plans))
	for _, plan := range plans {
		copyPlan := plan
		items = append(items, toProtoPlan(&copyPlan))
	}

	return &appv1.ListPlansResponse{Plans: items}, nil
}

func (s *appServices) ListPlayerConfigs(ctx context.Context, _ *appv1.ListPlayerConfigsRequest) (*appv1.ListPlayerConfigsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	var items []model.PlayerConfig
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", result.UserID).
		Order("is_default DESC").
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		s.logger.Error("Failed to list player configs", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load player configs")
	}

	payload := make([]*appv1.PlayerConfig, 0, len(items))
	for _, item := range items {
		copyItem := item
		payload = append(payload, toProtoPlayerConfig(&copyItem))
	}

	return &appv1.ListPlayerConfigsResponse{Configs: payload}, nil
}

func (s *appServices) CreatePlayerConfig(ctx context.Context, req *appv1.CreatePlayerConfigRequest) (*appv1.CreatePlayerConfigResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name is required")
	}

	item := &model.PlayerConfig{
		ID:            uuid.New().String(),
		UserID:        result.UserID,
		Name:          name,
		Description:   nullableTrimmedString(req.Description),
		Autoplay:      req.GetAutoplay(),
		Loop:          req.GetLoop(),
		Muted:         req.GetMuted(),
		ShowControls:  model.BoolPtr(req.GetShowControls()),
		Pip:           model.BoolPtr(req.GetPip()),
		Airplay:       model.BoolPtr(req.GetAirplay()),
		Chromecast:    model.BoolPtr(req.GetChromecast()),
		IsActive:      model.BoolPtr(req.IsActive == nil || *req.IsActive),
		IsDefault:     req.IsDefault != nil && *req.IsDefault,
		EncrytionM3u8: model.BoolPtr(req.EncrytionM3U8 == nil || *req.EncrytionM3U8),
		LogoURL:       nullableTrimmedString(req.LogoUrl),
	}
	if !playerConfigIsActive(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := lockUserForUpdate(ctx, tx, result.UserID)
		if err != nil {
			return err
		}

		var configCount int64
		if err := tx.WithContext(ctx).
			Model(&model.PlayerConfig{}).
			Where("user_id = ?", result.UserID).
			Count(&configCount).Error; err != nil {
			return err
		}
		if err := playerConfigActionAllowed(lockedUser, configCount, "create"); err != nil {
			return err
		}

		if item.IsDefault {
			if err := unsetDefaultPlayerConfigs(tx, result.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		s.logger.Error("Failed to create player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	return &appv1.CreatePlayerConfigResponse{Config: toProtoPlayerConfig(item)}, nil
}

func (s *appServices) UpdatePlayerConfig(ctx context.Context, req *appv1.UpdatePlayerConfigRequest) (*appv1.UpdatePlayerConfigResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name is required")
	}

	var item model.PlayerConfig
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := lockUserForUpdate(ctx, tx, result.UserID)
		if err != nil {
			return err
		}

		var configCount int64
		if err := tx.WithContext(ctx).
			Model(&model.PlayerConfig{}).
			Where("user_id = ?", result.UserID).
			Count(&configCount).Error; err != nil {
			return err
		}

		if err := tx.WithContext(ctx).Where("id = ? AND user_id = ?", id, result.UserID).First(&item).Error; err != nil {
			return err
		}

		action := "update"
		wasActive := playerConfigIsActive(item.IsActive)
		if req.IsActive != nil && *req.IsActive != wasActive {
			action = "toggle-active"
		}
		if req.IsDefault != nil && *req.IsDefault {
			action = "set-default"
		}
		if err := playerConfigActionAllowed(lockedUser, configCount, action); err != nil {
			return err
		}

		item.Name = name
		item.Description = nullableTrimmedString(req.Description)
		item.Autoplay = req.GetAutoplay()
		item.Loop = req.GetLoop()
		item.Muted = req.GetMuted()
		item.ShowControls = model.BoolPtr(req.GetShowControls())
		item.Pip = model.BoolPtr(req.GetPip())
		item.Airplay = model.BoolPtr(req.GetAirplay())
		item.Chromecast = model.BoolPtr(req.GetChromecast())
		if req.EncrytionM3U8 != nil {
			item.EncrytionM3u8 = model.BoolPtr(*req.EncrytionM3U8)
		}
		if req.LogoUrl != nil {
			item.LogoURL = nullableTrimmedString(req.LogoUrl)
		}
		if req.IsActive != nil {
			item.IsActive = model.BoolPtr(*req.IsActive)
		}
		if req.IsDefault != nil {
			item.IsDefault = *req.IsDefault
		}
		if !playerConfigIsActive(item.IsActive) {
			item.IsDefault = false
		}

		if item.IsDefault {
			if err := unsetDefaultPlayerConfigs(tx, result.UserID, item.ID); err != nil {
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
		s.logger.Error("Failed to update player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	return &appv1.UpdatePlayerConfigResponse{Config: toProtoPlayerConfig(&item)}, nil
}

func (s *appServices) DeletePlayerConfig(ctx context.Context, req *appv1.DeletePlayerConfigRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := lockUserForUpdate(ctx, tx, result.UserID)
		if err != nil {
			return err
		}

		var configCount int64
		if err := tx.WithContext(ctx).
			Model(&model.PlayerConfig{}).
			Where("user_id = ?", result.UserID).
			Count(&configCount).Error; err != nil {
			return err
		}
		if err := playerConfigActionAllowed(lockedUser, configCount, "delete"); err != nil {
			return err
		}

		res := tx.Where("id = ? AND user_id = ?", id, result.UserID).Delete(&model.PlayerConfig{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		s.logger.Error("Failed to delete player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete player config")
	}

	return messageResponse("Player config deleted"), nil
}
