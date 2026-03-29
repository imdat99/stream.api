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

func (s *notificationsAppService) ListNotifications(ctx context.Context, _ *appv1.ListNotificationsRequest) (*appv1.ListNotificationsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.notificationRepo.ListByUser(ctx, result.UserID)
	if err != nil {
		s.logger.Error("Failed to list notifications", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load notifications")
	}

	items := make([]*appv1.Notification, 0, len(rows))
	for _, row := range rows {
		items = append(items, toProtoNotification(row))
	}

	return &appv1.ListNotificationsResponse{Notifications: items}, nil
}
func (s *notificationsAppService) MarkNotificationRead(ctx context.Context, req *appv1.MarkNotificationReadRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	rowsAffected, err := s.notificationRepo.MarkReadByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		s.logger.Error("Failed to update notification", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update notification")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	return messageResponse("Notification updated"), nil
}
func (s *notificationsAppService) MarkAllNotificationsRead(ctx context.Context, _ *appv1.MarkAllNotificationsReadRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.notificationRepo.MarkAllReadByUser(ctx, result.UserID); err != nil {
		s.logger.Error("Failed to mark all notifications as read", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update notifications")
	}

	return messageResponse("All notifications marked as read"), nil
}
func (s *notificationsAppService) DeleteNotification(ctx context.Context, req *appv1.DeleteNotificationRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	rowsAffected, err := s.notificationRepo.DeleteByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		s.logger.Error("Failed to delete notification", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete notification")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Notification not found")
	}

	return messageResponse("Notification deleted"), nil
}
func (s *notificationsAppService) ClearNotifications(ctx context.Context, _ *appv1.ClearNotificationsRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.notificationRepo.DeleteAllByUser(ctx, result.UserID); err != nil {
		s.logger.Error("Failed to clear notifications", "error", err)
		return nil, status.Error(codes.Internal, "Failed to clear notifications")
	}

	return messageResponse("All notifications deleted"), nil
}
func (s *domainsAppService) ListDomains(ctx context.Context, _ *appv1.ListDomainsRequest) (*appv1.ListDomainsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.domainRepository.ListByUser(ctx, result.UserID)
	if err != nil {
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
func (s *domainsAppService) CreateDomain(ctx context.Context, req *appv1.CreateDomainRequest) (*appv1.CreateDomainResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	name := normalizeDomain(req.GetName())
	if name == "" || !strings.Contains(name, ".") || strings.ContainsAny(name, "/ ") {
		return nil, status.Error(codes.InvalidArgument, "Invalid domain")
	}

	count, err := s.domainRepository.CountByUserAndName(ctx, result.UserID, name)
	if err != nil {
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
	if err := s.domainRepository.Create(ctx, item); err != nil {
		s.logger.Error("Failed to create domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create domain")
	}

	return &appv1.CreateDomainResponse{Domain: toProtoDomain(item)}, nil
}
func (s *domainsAppService) DeleteDomain(ctx context.Context, req *appv1.DeleteDomainRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Domain not found")
	}

	rowsAffected, err := s.domainRepository.DeleteByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		s.logger.Error("Failed to delete domain", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete domain")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Domain not found")
	}

	return messageResponse("Domain deleted"), nil
}
func (s *adTemplatesAppService) ListAdTemplates(ctx context.Context, _ *appv1.ListAdTemplatesRequest) (*appv1.ListAdTemplatesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	items, err := s.adTemplateRepository.ListByUser(ctx, result.UserID)
	if err != nil {
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
func (s *adTemplatesAppService) CreateAdTemplate(ctx context.Context, req *appv1.CreateAdTemplateRequest) (*appv1.CreateAdTemplateResponse, error) {
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

	if err := s.adTemplateRepository.CreateWithDefault(ctx, result.UserID, item); err != nil {
		s.logger.Error("Failed to create ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	return &appv1.CreateAdTemplateResponse{Template: toProtoAdTemplate(item)}, nil
}
func (s *adTemplatesAppService) UpdateAdTemplate(ctx context.Context, req *appv1.UpdateAdTemplateRequest) (*appv1.UpdateAdTemplateResponse, error) {
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

	item, err := s.adTemplateRepository.GetByIDAndUser(ctx, id, result.UserID)
	if err != nil {
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

	if err := s.adTemplateRepository.SaveWithDefault(ctx, result.UserID, item); err != nil {
		s.logger.Error("Failed to update ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	return &appv1.UpdateAdTemplateResponse{Template: toProtoAdTemplate(item)}, nil
}
func (s *adTemplatesAppService) DeleteAdTemplate(ctx context.Context, req *appv1.DeleteAdTemplateRequest) (*appv1.MessageResponse, error) {
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

	if err := s.adTemplateRepository.DeleteByIDAndUserAndClearVideos(ctx, id, result.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		s.logger.Error("Failed to delete ad template", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete ad template")
	}

	return messageResponse("Ad template deleted"), nil
}
func (s *popupAdsAppService) ListPopupAds(ctx context.Context, req *appv1.ListPopupAdsRequest) (*appv1.ListPopupAdsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	items, total, err := s.popupAdRepository.ListByUser(ctx, result.UserID, limit, offset)
	if err != nil {
		s.logger.Error("Failed to list popup ads", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load popup ads")
	}

	payload := make([]*appv1.PopupAd, 0, len(items))
	for _, item := range items {
		copyItem := item
		payload = append(payload, toProtoPopupAd(&copyItem))
	}

	return &appv1.ListPopupAdsResponse{Items: payload, Total: total, Page: page, Limit: limit}, nil
}
func (s *popupAdsAppService) CreatePopupAd(ctx context.Context, req *appv1.CreatePopupAdRequest) (*appv1.CreatePopupAdResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	popupType := strings.ToLower(strings.TrimSpace(req.GetType()))
	label := strings.TrimSpace(req.GetLabel())
	value := strings.TrimSpace(req.GetValue())
	maxTriggers := int32(3)
	if req.MaxTriggersPerSession != nil {
		maxTriggers = *req.MaxTriggersPerSession
	}
	if popupType != "url" && popupType != "script" {
		return nil, status.Error(codes.InvalidArgument, "Popup ad type must be url or script")
	}
	if label == "" || value == "" {
		return nil, status.Error(codes.InvalidArgument, "Label and value are required")
	}
	if maxTriggers < 1 {
		return nil, status.Error(codes.InvalidArgument, "Max triggers per session must be greater than 0")
	}

	item := &model.PopupAd{
		ID:                    uuid.New().String(),
		UserID:                result.UserID,
		Type:                  popupType,
		Label:                 label,
		Value:                 value,
		IsActive:              model.BoolPtr(req.IsActive == nil || *req.IsActive),
		MaxTriggersPerSession: int32Ptr(maxTriggers),
	}
	if err := s.popupAdRepository.Create(ctx, item); err != nil {
		s.logger.Error("Failed to create popup ad", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save popup ad")
	}

	return &appv1.CreatePopupAdResponse{Item: toProtoPopupAd(item)}, nil
}
func (s *popupAdsAppService) UpdatePopupAd(ctx context.Context, req *appv1.UpdatePopupAdRequest) (*appv1.UpdatePopupAdResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Popup ad not found")
	}
	popupType := strings.ToLower(strings.TrimSpace(req.GetType()))
	label := strings.TrimSpace(req.GetLabel())
	value := strings.TrimSpace(req.GetValue())
	if popupType != "url" && popupType != "script" {
		return nil, status.Error(codes.InvalidArgument, "Popup ad type must be url or script")
	}
	if label == "" || value == "" {
		return nil, status.Error(codes.InvalidArgument, "Label and value are required")
	}
	if req.MaxTriggersPerSession != nil && *req.MaxTriggersPerSession < 1 {
		return nil, status.Error(codes.InvalidArgument, "Max triggers per session must be greater than 0")
	}

	item, err := s.popupAdRepository.GetByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Popup ad not found")
		}
		s.logger.Error("Failed to load popup ad", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save popup ad")
	}

	item.Type = popupType
	item.Label = label
	item.Value = value
	if req.IsActive != nil {
		item.IsActive = model.BoolPtr(*req.IsActive)
	}
	if req.MaxTriggersPerSession != nil {
		item.MaxTriggersPerSession = int32Ptr(*req.MaxTriggersPerSession)
	}
	if err := s.popupAdRepository.Save(ctx, item); err != nil {
		s.logger.Error("Failed to update popup ad", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save popup ad")
	}

	return &appv1.UpdatePopupAdResponse{Item: toProtoPopupAd(item)}, nil
}
func (s *popupAdsAppService) DeletePopupAd(ctx context.Context, req *appv1.DeletePopupAdRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Popup ad not found")
	}
	rowsAffected, err := s.popupAdRepository.DeleteByIDAndUser(ctx, id, result.UserID)
	if err != nil {
		s.logger.Error("Failed to delete popup ad", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete popup ad")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Popup ad not found")
	}
	return messageResponse("Popup ad deleted"), nil
}
func (s *popupAdsAppService) GetActivePopupAd(ctx context.Context, _ *appv1.GetActivePopupAdRequest) (*appv1.GetActivePopupAdResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	item, err := s.popupAdRepository.GetActiveByUser(ctx, result.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &appv1.GetActivePopupAdResponse{}, nil
		}
		s.logger.Error("Failed to load active popup ad", "error", err)
		return nil, status.Error(codes.Internal, "Failed to load popup ad")
	}
	return &appv1.GetActivePopupAdResponse{Item: toProtoPopupAd(item)}, nil
}
func (s *plansAppService) ListPlans(ctx context.Context, _ *appv1.ListPlansRequest) (*appv1.ListPlansResponse, error) {
	if _, err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	plans, err := s.planRepository.ListActive(ctx)
	if err != nil {
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

func (s *playerConfigsAppService) ListPlayerConfigs(ctx context.Context, _ *appv1.ListPlayerConfigsRequest) (*appv1.ListPlayerConfigsResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	items, err := s.playerConfigRepo.ListByUser(ctx, result.UserID)
	if err != nil {
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

func (s *playerConfigsAppService) CreatePlayerConfig(ctx context.Context, req *appv1.CreatePlayerConfigRequest) (*appv1.CreatePlayerConfigResponse, error) {
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

	if err := s.playerConfigRepo.CreateManaged(ctx, result.UserID, item, func(lockedUser *model.User, configCount int64) error {
		return playerConfigActionAllowed(lockedUser, configCount, "create")
	}); err != nil {
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		s.logger.Error("Failed to create player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	return &appv1.CreatePlayerConfigResponse{Config: toProtoPlayerConfig(item)}, nil
}

func (s *playerConfigsAppService) UpdatePlayerConfig(ctx context.Context, req *appv1.UpdatePlayerConfigRequest) (*appv1.UpdatePlayerConfigResponse, error) {
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

	item, err := s.playerConfigRepo.UpdateManaged(ctx, result.UserID, id, func(item *model.PlayerConfig, lockedUser *model.User, configCount int64) error {
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
		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		s.logger.Error("Failed to update player config", "error", err)
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	return &appv1.UpdatePlayerConfigResponse{Config: toProtoPlayerConfig(item)}, nil
}

func (s *playerConfigsAppService) DeletePlayerConfig(ctx context.Context, req *appv1.DeletePlayerConfigRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	if err := s.playerConfigRepo.DeleteManaged(ctx, result.UserID, id, func(lockedUser *model.User, configCount int64) error {
		return playerConfigActionAllowed(lockedUser, configCount, "delete")
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
