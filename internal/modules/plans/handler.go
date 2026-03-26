package plans

import (
	"context"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	appv1.UnimplementedPlansServiceServer
	module *Module
}

var _ appv1.PlansServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) ListPlans(ctx context.Context, _ *appv1.ListPlansRequest) (*appv1.ListPlansResponse, error) {
	result, err := h.module.ListPlans(ctx)
	if err != nil {
		return nil, err
	}
	return presentListPlansResponse(result), nil
}

func (h *Handler) ListAdminPlans(ctx context.Context, _ *appv1.ListAdminPlansRequest) (*appv1.ListAdminPlansResponse, error) {
	result, err := h.module.ListAdminPlans(ctx)
	if err != nil {
		return nil, err
	}
	return presentListAdminPlansResponse(result), nil
}

func (h *Handler) CreateAdminPlan(ctx context.Context, req *appv1.CreateAdminPlanRequest) (*appv1.CreateAdminPlanResponse, error) {
	result, err := h.module.CreateAdminPlan(ctx, CreateAdminPlanCommand{Name: req.GetName(), Description: req.Description, Features: req.GetFeatures(), Price: req.GetPrice(), Cycle: req.GetCycle(), StorageLimit: req.GetStorageLimit(), UploadLimit: req.GetUploadLimit(), IsActive: req.GetIsActive()})
	if err != nil {
		return nil, err
	}
	return presentCreateAdminPlanResponse(*result), nil
}

func (h *Handler) UpdateAdminPlan(ctx context.Context, req *appv1.UpdateAdminPlanRequest) (*appv1.UpdateAdminPlanResponse, error) {
	result, err := h.module.UpdateAdminPlan(ctx, UpdateAdminPlanCommand{ID: req.GetId(), Name: req.GetName(), Description: req.Description, Features: req.GetFeatures(), Price: req.GetPrice(), Cycle: req.GetCycle(), StorageLimit: req.GetStorageLimit(), UploadLimit: req.GetUploadLimit(), IsActive: req.GetIsActive()})
	if err != nil {
		return nil, err
	}
	return presentUpdateAdminPlanResponse(*result), nil
}

func (h *Handler) DeleteAdminPlan(ctx context.Context, req *appv1.DeleteAdminPlanRequest) (*appv1.DeleteAdminPlanResponse, error) {
	result, err := h.module.DeleteAdminPlan(ctx, DeleteAdminPlanCommand{ID: req.GetId()})
	if err != nil {
		return nil, err
	}
	return presentDeleteAdminPlanResponse(result), nil
}
