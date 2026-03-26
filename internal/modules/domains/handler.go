package domains

import (
	"context"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	appv1.UnimplementedDomainsServiceServer
	module *Module
}

var _ appv1.DomainsServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) ListDomains(ctx context.Context, _ *appv1.ListDomainsRequest) (*appv1.ListDomainsResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.ListDomains(ctx, ListDomainsQuery{UserID: result.UserID})
	if err != nil {
		return nil, err
	}
	return presentListDomainsResponse(payload), nil
}

func (h *Handler) CreateDomain(ctx context.Context, req *appv1.CreateDomainRequest) (*appv1.CreateDomainResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.CreateDomain(ctx, CreateDomainCommand{UserID: result.UserID, Name: req.GetName()})
	if err != nil {
		return nil, err
	}
	return presentCreateDomainResponse(*payload), nil
}

func (h *Handler) DeleteDomain(ctx context.Context, req *appv1.DeleteDomainRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.module.DeleteDomain(ctx, DeleteDomainCommand{UserID: result.UserID, ID: req.GetId()}); err != nil {
		return nil, err
	}
	return commonMessage("Domain deleted"), nil
}

func commonMessage(message string) *appv1.MessageResponse {
	return &appv1.MessageResponse{Message: message}
}
