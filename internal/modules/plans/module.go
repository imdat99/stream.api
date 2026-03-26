package plans

import (
	"context"
	"errors"
	"strings"

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

func (m *Module) ListPlans(ctx context.Context) (*ListPlansResult, error) {
	if _, err := m.runtime.Authenticate(ctx); err != nil {
		return nil, err
	}
	var plans []model.Plan
	if err := m.runtime.DB().WithContext(ctx).Where("is_active = ?", true).Find(&plans).Error; err != nil {
		m.runtime.Logger().Error("Failed to fetch plans", "error", err)
		return nil, status.Error(codes.Internal, "Failed to fetch plans")
	}
	items := make([]PlanView, 0, len(plans))
	for i := range plans {
		items = append(items, PlanView{Plan: &plans[i]})
	}
	return &ListPlansResult{Items: items}, nil
}

func (m *Module) ListAdminPlans(ctx context.Context) (*ListAdminPlansResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	var plans []model.Plan
	if err := m.runtime.DB().WithContext(ctx).Order("price ASC").Find(&plans).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list plans")
	}
	items := make([]AdminPlanView, 0, len(plans))
	for i := range plans {
		payload, err := m.BuildAdminPlan(ctx, &plans[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list plans")
		}
		items = append(items, payload)
	}
	return &ListAdminPlansResult{Items: items}, nil
}

func (m *Module) CreateAdminPlan(ctx context.Context, cmd CreateAdminPlanCommand) (*AdminPlanView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if msg := validateAdminPlanInput(cmd.Name, cmd.Cycle, cmd.Price, cmd.StorageLimit, cmd.UploadLimit); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	plan := &model.Plan{ID: uuid.New().String(), Name: strings.TrimSpace(cmd.Name), Description: common.NullableTrimmedStringPtr(cmd.Description), Features: append([]string(nil), cmd.Features...), Price: cmd.Price, Cycle: strings.TrimSpace(cmd.Cycle), StorageLimit: cmd.StorageLimit, UploadLimit: cmd.UploadLimit, DurationLimit: 0, QualityLimit: "", IsActive: model.BoolPtr(cmd.IsActive)}
	if err := m.runtime.DB().WithContext(ctx).Create(plan).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to create plan")
	}
	payload, err := m.BuildAdminPlan(ctx, plan)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create plan")
	}
	return &payload, nil
}

func (m *Module) UpdateAdminPlan(ctx context.Context, cmd UpdateAdminPlanCommand) (*AdminPlanView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Plan not found")
	}
	if msg := validateAdminPlanInput(cmd.Name, cmd.Cycle, cmd.Price, cmd.StorageLimit, cmd.UploadLimit); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	var plan model.Plan
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}
	plan.Name = strings.TrimSpace(cmd.Name)
	plan.Description = common.NullableTrimmedStringPtr(cmd.Description)
	plan.Features = append([]string(nil), cmd.Features...)
	plan.Price = cmd.Price
	plan.Cycle = strings.TrimSpace(cmd.Cycle)
	plan.StorageLimit = cmd.StorageLimit
	plan.UploadLimit = cmd.UploadLimit
	plan.IsActive = model.BoolPtr(cmd.IsActive)
	if err := m.runtime.DB().WithContext(ctx).Save(&plan).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}
	payload, err := m.BuildAdminPlan(ctx, &plan)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}
	return &payload, nil
}

func (m *Module) DeleteAdminPlan(ctx context.Context, cmd DeleteAdminPlanCommand) (*DeleteAdminPlanResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Plan not found")
	}
	var plan model.Plan
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	var paymentCount int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", cmd.ID).Count(&paymentCount).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	var subscriptionCount int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", cmd.ID).Count(&subscriptionCount).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	if paymentCount > 0 || subscriptionCount > 0 {
		inactive := false
		if err := m.runtime.DB().WithContext(ctx).Model(&model.Plan{}).Where("id = ?", cmd.ID).Update("is_active", inactive).Error; err != nil {
			return nil, status.Error(codes.Internal, "Failed to deactivate plan")
		}
		return &DeleteAdminPlanResult{Message: "Plan deactivated", Mode: "deactivated"}, nil
	}
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", cmd.ID).Delete(&model.Plan{}).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	return &DeleteAdminPlanResult{Message: "Plan deleted", Mode: "deleted"}, nil
}

func (m *Module) BuildAdminPlan(ctx context.Context, plan *model.Plan) (AdminPlanView, error) {
	if plan == nil {
		return AdminPlanView{}, nil
	}
	userCount, paymentCount, subscriptionCount, err := m.loadAdminPlanUsageCounts(ctx, plan.ID)
	if err != nil {
		return AdminPlanView{}, err
	}
	return AdminPlanView{ID: plan.ID, Name: plan.Name, Description: common.NullableTrimmedString(plan.Description), Features: append([]string(nil), plan.Features...), Price: plan.Price, Cycle: plan.Cycle, StorageLimit: plan.StorageLimit, UploadLimit: plan.UploadLimit, DurationLimit: int32(plan.DurationLimit), QualityLimit: plan.QualityLimit, IsActive: common.BoolValue(plan.IsActive), UserCount: userCount, PaymentCount: paymentCount, SubscriptionCount: subscriptionCount}, nil
}

func (m *Module) loadAdminPlanUsageCounts(ctx context.Context, planID string) (int64, int64, int64, error) {
	var userCount int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.User{}).Where("plan_id = ?", planID).Count(&userCount).Error; err != nil {
		return 0, 0, 0, err
	}
	var paymentCount int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", planID).Count(&paymentCount).Error; err != nil {
		return 0, 0, 0, err
	}
	var subscriptionCount int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", planID).Count(&subscriptionCount).Error; err != nil {
		return 0, 0, 0, err
	}
	return userCount, paymentCount, subscriptionCount, nil
}

func validateAdminPlanInput(name, cycle string, price float64, storageLimit int64, uploadLimit int32) string {
	if strings.TrimSpace(name) == "" {
		return "Name is required"
	}
	if strings.TrimSpace(cycle) == "" {
		return "Cycle is required"
	}
	if price < 0 {
		return "Price must be greater than or equal to 0"
	}
	if storageLimit <= 0 {
		return "Storage limit must be greater than 0"
	}
	if uploadLimit <= 0 {
		return "Upload limit must be greater than 0"
	}
	return ""
}
