package playerconfigs

import (
	"context"
	"strings"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	appv1.UnimplementedPlayerConfigsServiceServer
	module *Module
}

var _ appv1.PlayerConfigsServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) ListPlayerConfigs(ctx context.Context, _ *appv1.ListPlayerConfigsRequest) (*appv1.ListPlayerConfigsResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.ListPlayerConfigs(ctx, ListPlayerConfigsQuery{UserID: result.UserID})
	if err != nil {
		return nil, err
	}
	return presentListPlayerConfigsResponse(payload), nil
}

func (h *Handler) CreatePlayerConfig(ctx context.Context, req *appv1.CreatePlayerConfigRequest) (*appv1.CreatePlayerConfigResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.CreatePlayerConfig(ctx, CreatePlayerConfigCommand{UserID: result.UserID, Name: req.GetName(), Description: req.Description, Autoplay: req.GetAutoplay(), Loop: req.GetLoop(), Muted: req.GetMuted(), ShowControls: req.GetShowControls(), Pip: req.GetPip(), Airplay: req.GetAirplay(), Chromecast: req.GetChromecast(), IsActive: req.IsActive, IsDefault: req.IsDefault, EncrytionM3U8: req.EncrytionM3U8, LogoURL: req.LogoUrl})
	if err != nil {
		return nil, err
	}
	return presentCreatePlayerConfigResponse(*payload), nil
}

func (h *Handler) UpdatePlayerConfig(ctx context.Context, req *appv1.UpdatePlayerConfigRequest) (*appv1.UpdatePlayerConfigResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.UpdatePlayerConfig(ctx, UpdatePlayerConfigCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId()), Name: req.GetName(), Description: req.Description, Autoplay: req.GetAutoplay(), Loop: req.GetLoop(), Muted: req.GetMuted(), ShowControls: req.GetShowControls(), Pip: req.GetPip(), Airplay: req.GetAirplay(), Chromecast: req.GetChromecast(), IsActive: req.IsActive, IsDefault: req.IsDefault, EncrytionM3U8: req.EncrytionM3U8, LogoURL: req.LogoUrl})
	if err != nil {
		return nil, err
	}
	return presentUpdatePlayerConfigResponse(*payload), nil
}

func (h *Handler) DeletePlayerConfig(ctx context.Context, req *appv1.DeletePlayerConfigRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.module.DeletePlayerConfig(ctx, DeletePlayerConfigCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Player config deleted"}, nil
}

func (h *Handler) ListAdminPlayerConfigs(ctx context.Context, req *appv1.ListAdminPlayerConfigsRequest) (*appv1.ListAdminPlayerConfigsResponse, error) {
	payload, err := h.module.ListAdminPlayerConfigs(ctx, ListAdminPlayerConfigsQuery{Page: req.GetPage(), Limit: req.GetLimit(), Search: req.Search, UserID: req.UserId})
	if err != nil {
		return nil, err
	}
	return presentListAdminPlayerConfigsResponse(payload), nil
}

func (h *Handler) GetAdminPlayerConfig(ctx context.Context, req *appv1.GetAdminPlayerConfigRequest) (*appv1.GetAdminPlayerConfigResponse, error) {
	payload, err := h.module.GetAdminPlayerConfig(ctx, GetAdminPlayerConfigQuery{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentGetAdminPlayerConfigResponse(*payload), nil
}

func (h *Handler) CreateAdminPlayerConfig(ctx context.Context, req *appv1.CreateAdminPlayerConfigRequest) (*appv1.CreateAdminPlayerConfigResponse, error) {
	payload, err := h.module.CreateAdminPlayerConfig(ctx, CreateAdminPlayerConfigCommand{UserID: strings.TrimSpace(req.GetUserId()), Name: req.GetName(), Description: req.Description, Autoplay: req.GetAutoplay(), Loop: req.GetLoop(), Muted: req.GetMuted(), ShowControls: req.GetShowControls(), Pip: req.GetPip(), Airplay: req.GetAirplay(), Chromecast: req.GetChromecast(), IsActive: req.GetIsActive(), IsDefault: req.GetIsDefault(), EncrytionM3U8: req.EncrytionM3U8, LogoURL: req.LogoUrl})
	if err != nil {
		return nil, err
	}
	return presentCreateAdminPlayerConfigResponse(*payload), nil
}

func (h *Handler) UpdateAdminPlayerConfig(ctx context.Context, req *appv1.UpdateAdminPlayerConfigRequest) (*appv1.UpdateAdminPlayerConfigResponse, error) {
	payload, err := h.module.UpdateAdminPlayerConfig(ctx, UpdateAdminPlayerConfigCommand{ID: strings.TrimSpace(req.GetId()), UserID: strings.TrimSpace(req.GetUserId()), Name: req.GetName(), Description: req.Description, Autoplay: req.GetAutoplay(), Loop: req.GetLoop(), Muted: req.GetMuted(), ShowControls: req.GetShowControls(), Pip: req.GetPip(), Airplay: req.GetAirplay(), Chromecast: req.GetChromecast(), IsActive: req.GetIsActive(), IsDefault: req.GetIsDefault(), EncrytionM3U8: req.EncrytionM3U8, LogoURL: req.LogoUrl})
	if err != nil {
		return nil, err
	}
	return presentUpdateAdminPlayerConfigResponse(*payload), nil
}

func (h *Handler) DeleteAdminPlayerConfig(ctx context.Context, req *appv1.DeleteAdminPlayerConfigRequest) (*appv1.MessageResponse, error) {
	if err := h.module.DeleteAdminPlayerConfig(ctx, DeleteAdminPlayerConfigCommand{ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Player config deleted"}, nil
}
