package adtemplates

import (
	"context"
	"strings"

	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

type Handler struct {
	appv1.UnimplementedAdTemplatesServiceServer
	module *Module
}

var _ appv1.AdTemplatesServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) ListAdTemplates(ctx context.Context, _ *appv1.ListAdTemplatesRequest) (*appv1.ListAdTemplatesResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.ListAdTemplates(ctx, ListAdTemplatesQuery{UserID: result.UserID})
	if err != nil {
		return nil, err
	}
	return presentListAdTemplatesResponse(payload), nil
}

func (h *Handler) CreateAdTemplate(ctx context.Context, req *appv1.CreateAdTemplateRequest) (*appv1.CreateAdTemplateResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := common.EnsurePaidPlan(result.User); err != nil {
		return nil, err
	}
	payload, err := h.module.CreateAdTemplate(ctx, CreateAdTemplateCommand{
		UserID:      result.UserID,
		Name:        req.GetName(),
		Description: req.Description,
		VastTagURL:  req.GetVastTagUrl(),
		AdFormat:    req.GetAdFormat(),
		Duration:    req.Duration,
		IsActive:    req.IsActive,
		IsDefault:   req.IsDefault,
	})
	if err != nil {
		return nil, err
	}
	return presentCreateAdTemplateResponse(*payload), nil
}

func (h *Handler) UpdateAdTemplate(ctx context.Context, req *appv1.UpdateAdTemplateRequest) (*appv1.UpdateAdTemplateResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := common.EnsurePaidPlan(result.User); err != nil {
		return nil, err
	}
	payload, err := h.module.UpdateAdTemplate(ctx, UpdateAdTemplateCommand{
		UserID:      result.UserID,
		ID:          strings.TrimSpace(req.GetId()),
		Name:        req.GetName(),
		Description: req.Description,
		VastTagURL:  req.GetVastTagUrl(),
		AdFormat:    req.GetAdFormat(),
		Duration:    req.Duration,
		IsActive:    req.IsActive,
		IsDefault:   req.IsDefault,
	})
	if err != nil {
		return nil, err
	}
	return presentUpdateAdTemplateResponse(*payload), nil
}

func (h *Handler) DeleteAdTemplate(ctx context.Context, req *appv1.DeleteAdTemplateRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := common.EnsurePaidPlan(result.User); err != nil {
		return nil, err
	}
	if err := h.module.DeleteAdTemplate(ctx, DeleteAdTemplateCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Ad template deleted"}, nil
}

func (h *Handler) ListAdminAdTemplates(ctx context.Context, req *appv1.ListAdminAdTemplatesRequest) (*appv1.ListAdminAdTemplatesResponse, error) {
	payload, err := h.module.ListAdminAdTemplates(ctx, ListAdminAdTemplatesQuery{Page: req.GetPage(), Limit: req.GetLimit(), Search: req.Search, UserID: req.UserId})
	if err != nil {
		return nil, err
	}
	return presentListAdminAdTemplatesResponse(payload), nil
}

func (h *Handler) GetAdminAdTemplate(ctx context.Context, req *appv1.GetAdminAdTemplateRequest) (*appv1.GetAdminAdTemplateResponse, error) {
	payload, err := h.module.GetAdminAdTemplate(ctx, GetAdminAdTemplateQuery{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentGetAdminAdTemplateResponse(*payload), nil
}

func (h *Handler) CreateAdminAdTemplate(ctx context.Context, req *appv1.CreateAdminAdTemplateRequest) (*appv1.CreateAdminAdTemplateResponse, error) {
	payload, err := h.module.CreateAdminAdTemplate(ctx, CreateAdminAdTemplateCommand{
		UserID:      strings.TrimSpace(req.GetUserId()),
		Name:        req.GetName(),
		Description: req.Description,
		VastTagURL:  req.GetVastTagUrl(),
		AdFormat:    req.GetAdFormat(),
		Duration:    req.Duration,
		IsActive:    req.GetIsActive(),
		IsDefault:   req.GetIsDefault(),
	})
	if err != nil {
		return nil, err
	}
	return presentCreateAdminAdTemplateResponse(*payload), nil
}

func (h *Handler) UpdateAdminAdTemplate(ctx context.Context, req *appv1.UpdateAdminAdTemplateRequest) (*appv1.UpdateAdminAdTemplateResponse, error) {
	payload, err := h.module.UpdateAdminAdTemplate(ctx, UpdateAdminAdTemplateCommand{
		ID:          strings.TrimSpace(req.GetId()),
		UserID:      strings.TrimSpace(req.GetUserId()),
		Name:        req.GetName(),
		Description: req.Description,
		VastTagURL:  req.GetVastTagUrl(),
		AdFormat:    req.GetAdFormat(),
		Duration:    req.Duration,
		IsActive:    req.GetIsActive(),
		IsDefault:   req.GetIsDefault(),
	})
	if err != nil {
		return nil, err
	}
	return presentUpdateAdminAdTemplateResponse(*payload), nil
}

func (h *Handler) DeleteAdminAdTemplate(ctx context.Context, req *appv1.DeleteAdminAdTemplateRequest) (*appv1.MessageResponse, error) {
	if err := h.module.DeleteAdminAdTemplate(ctx, DeleteAdminAdTemplateCommand{ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Ad template deleted"}, nil
}
