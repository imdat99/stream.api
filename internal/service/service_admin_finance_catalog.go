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

func (s *appServices) ListAdminPayments(ctx context.Context, req *appv1.ListAdminPaymentsRequest) (*appv1.ListAdminPaymentsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	userID := strings.TrimSpace(req.GetUserId())
	statusFilter := strings.TrimSpace(req.GetStatus())

	payments, total, err := s.paymentRepository.ListForAdmin(ctx, userID, statusFilter, limit, offset)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to list payments")
	}

	items := make([]*appv1.AdminPayment, 0, len(payments))
	for _, payment := range payments {
		payload, err := s.buildAdminPayment(ctx, &payment)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list payments")
		}
		items = append(items, payload)
	}

	return &appv1.ListAdminPaymentsResponse{Payments: items, Total: total, Page: page, Limit: limit}, nil
}
func (s *appServices) GetAdminPayment(ctx context.Context, req *appv1.GetAdminPaymentRequest) (*appv1.GetAdminPaymentResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Payment not found")
	}

	payment, err := s.paymentRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Payment not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get payment")
	}

	payload, err := s.buildAdminPayment(ctx, payment)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get payment")
	}

	return &appv1.GetAdminPaymentResponse{Payment: payload}, nil
}
func (s *appServices) CreateAdminPayment(ctx context.Context, req *appv1.CreateAdminPaymentRequest) (*appv1.CreateAdminPaymentResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	userID := strings.TrimSpace(req.GetUserId())
	planID := strings.TrimSpace(req.GetPlanId())
	if userID == "" || planID == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID and plan ID are required")
	}
	if !isAllowedTermMonths(req.GetTermMonths()) {
		return nil, status.Error(codes.InvalidArgument, "Term months must be one of 1, 3, 6, or 12")
	}

	paymentMethod := normalizePaymentMethod(req.GetPaymentMethod())
	if paymentMethod == "" {
		return nil, status.Error(codes.InvalidArgument, "Payment method must be wallet or topup")
	}

	user, err := s.loadPaymentUserForAdmin(ctx, userID)
	if err != nil {
		return nil, err
	}
	planRecord, err := s.loadPaymentPlanForAdmin(ctx, planID)
	if err != nil {
		return nil, err
	}

	resultValue, err := s.executePaymentFlow(ctx, paymentExecutionInput{
		UserID:        user.ID,
		Plan:          planRecord,
		TermMonths:    req.GetTermMonths(),
		PaymentMethod: paymentMethod,
		TopupAmount:   req.TopupAmount,
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}

	payload, err := s.buildAdminPayment(ctx, resultValue.Payment)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	return &appv1.CreateAdminPaymentResponse{
		Payment:       payload,
		Subscription:  toProtoPlanSubscription(resultValue.Subscription),
		WalletBalance: resultValue.WalletBalance,
		InvoiceId:     resultValue.InvoiceID,
	}, nil
}
func (s *appServices) UpdateAdminPayment(ctx context.Context, req *appv1.UpdateAdminPaymentRequest) (*appv1.UpdateAdminPaymentResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Payment not found")
	}

	newStatus := strings.ToUpper(strings.TrimSpace(req.GetStatus()))
	if newStatus == "" {
		newStatus = "SUCCESS"
	}
	if newStatus != "SUCCESS" && newStatus != "FAILED" && newStatus != "PENDING" {
		return nil, status.Error(codes.InvalidArgument, "Invalid payment status")
	}

	payment, err := s.paymentRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Payment not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update payment")
	}

	currentStatus := strings.ToUpper(normalizePaymentStatus(payment.Status))
	if currentStatus != newStatus {
		if (currentStatus == "FAILED" || currentStatus == "PENDING") && newStatus == "SUCCESS" {
			return nil, status.Error(codes.InvalidArgument, "Cannot transition payment to SUCCESS from admin update; recreate through the payment flow instead")
		}
		payment.Status = model.StringPtr(newStatus)
		if err := s.paymentRepository.Save(ctx, payment); err != nil {
			return nil, status.Error(codes.Internal, "Failed to update payment")
		}
	}

	payload, err := s.buildAdminPayment(ctx, payment)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update payment")
	}
	return &appv1.UpdateAdminPaymentResponse{Payment: payload}, nil
}
func (s *appServices) ListAdminPlans(ctx context.Context, _ *appv1.ListAdminPlansRequest) (*appv1.ListAdminPlansResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	plans, err := s.planRepository.ListAll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to list plans")
	}

	items := make([]*appv1.AdminPlan, 0, len(plans))
	for i := range plans {
		payload, err := s.buildAdminPlan(ctx, &plans[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list plans")
		}
		items = append(items, payload)
	}
	return &appv1.ListAdminPlansResponse{Plans: items}, nil
}
func (s *appServices) CreateAdminPlan(ctx context.Context, req *appv1.CreateAdminPlanRequest) (*appv1.CreateAdminPlanResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	if msg := validateAdminPlanInput(req.GetName(), req.GetCycle(), req.GetPrice(), req.GetStorageLimit(), req.GetUploadLimit()); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	plan := &model.Plan{
		ID:            uuid.New().String(),
		Name:          strings.TrimSpace(req.GetName()),
		Description:   nullableTrimmedStringPtr(req.Description),
		Features:      append([]string(nil), req.GetFeatures()...),
		Price:         req.GetPrice(),
		Cycle:         strings.TrimSpace(req.GetCycle()),
		StorageLimit:  req.GetStorageLimit(),
		UploadLimit:   req.GetUploadLimit(),
		DurationLimit: 0,
		QualityLimit:  "",
		IsActive:      model.BoolPtr(req.GetIsActive()),
	}

	if err := s.planRepository.Create(ctx, plan); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create plan")
	}

	payload, err := s.buildAdminPlan(ctx, plan)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create plan")
	}
	return &appv1.CreateAdminPlanResponse{Plan: payload}, nil
}
func (s *appServices) UpdateAdminPlan(ctx context.Context, req *appv1.UpdateAdminPlanRequest) (*appv1.UpdateAdminPlanResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Plan not found")
	}
	if msg := validateAdminPlanInput(req.GetName(), req.GetCycle(), req.GetPrice(), req.GetStorageLimit(), req.GetUploadLimit()); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	plan, err := s.planRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}

	plan.Name = strings.TrimSpace(req.GetName())
	plan.Description = nullableTrimmedStringPtr(req.Description)
	plan.Features = append([]string(nil), req.GetFeatures()...)
	plan.Price = req.GetPrice()
	plan.Cycle = strings.TrimSpace(req.GetCycle())
	plan.StorageLimit = req.GetStorageLimit()
	plan.UploadLimit = req.GetUploadLimit()
	plan.IsActive = model.BoolPtr(req.GetIsActive())

	if err := s.planRepository.Save(ctx, plan); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}

	payload, err := s.buildAdminPlan(ctx, plan)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}
	return &appv1.UpdateAdminPlanResponse{Plan: payload}, nil
}
func (s *appServices) DeleteAdminPlan(ctx context.Context, req *appv1.DeleteAdminPlanRequest) (*appv1.DeleteAdminPlanResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Plan not found")
	}

	_, err := s.planRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}

	paymentCount, err := s.planRepository.CountPaymentsByPlan(ctx, id)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	subscriptionCount, err := s.planRepository.CountSubscriptionsByPlan(ctx, id)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}

	if paymentCount > 0 || subscriptionCount > 0 {
		inactive := false
		if err := s.planRepository.SetActive(ctx, id, inactive); err != nil {
			return nil, status.Error(codes.Internal, "Failed to deactivate plan")
		}
		return &appv1.DeleteAdminPlanResponse{Message: "Plan deactivated", Mode: "deactivated"}, nil
	}

	if err := s.planRepository.DeleteByID(ctx, id); err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	return &appv1.DeleteAdminPlanResponse{Message: "Plan deleted", Mode: "deleted"}, nil
}
func (s *appServices) ListAdminAdTemplates(ctx context.Context, req *appv1.ListAdminAdTemplatesRequest) (*appv1.ListAdminAdTemplatesResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	search := strings.TrimSpace(protoStringValue(req.Search))
	userID := strings.TrimSpace(protoStringValue(req.UserId))

	templates, total, err := s.adTemplateRepository.ListForAdmin(ctx, search, userID, limit, offset)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to list ad templates")
	}

	items := make([]*appv1.AdminAdTemplate, 0, len(templates))
	for i := range templates {
		payload, err := s.buildAdminAdTemplate(ctx, &templates[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list ad templates")
		}
		items = append(items, payload)
	}

	return &appv1.ListAdminAdTemplatesResponse{
		Templates: items,
		Total:     total,
		Page:      page,
		Limit:     limit,
	}, nil
}
func (s *appServices) GetAdminAdTemplate(ctx context.Context, req *appv1.GetAdminAdTemplateRequest) (*appv1.GetAdminAdTemplateResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}

	item, err := s.adTemplateRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load ad template")
	}

	payload, err := s.buildAdminAdTemplate(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load ad template")
	}
	return &appv1.GetAdminAdTemplateResponse{Template: payload}, nil
}
func (s *appServices) CreateAdminAdTemplate(ctx context.Context, req *appv1.CreateAdminAdTemplateRequest) (*appv1.CreateAdminAdTemplateResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	duration := req.Duration
	if msg := validateAdminAdTemplateInput(req.GetUserId(), req.GetName(), req.GetVastTagUrl(), req.GetAdFormat(), duration); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	user, err := s.userRepository.GetByID(ctx, strings.TrimSpace(req.GetUserId()))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	item := &model.AdTemplate{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Name:        strings.TrimSpace(req.GetName()),
		Description: nullableTrimmedStringPtr(req.Description),
		VastTagURL:  strings.TrimSpace(req.GetVastTagUrl()),
		AdFormat:    model.StringPtr(normalizeAdFormat(req.GetAdFormat())),
		Duration:    duration,
		IsActive:    model.BoolPtr(req.GetIsActive()),
		IsDefault:   req.GetIsDefault(),
	}
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.adTemplateRepository.CreateWithDefault(ctx, item.UserID, item); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	payload, err := s.buildAdminAdTemplate(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &appv1.CreateAdminAdTemplateResponse{Template: payload}, nil
}
func (s *appServices) UpdateAdminAdTemplate(ctx context.Context, req *appv1.UpdateAdminAdTemplateRequest) (*appv1.UpdateAdminAdTemplateResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}
	duration := req.Duration
	if msg := validateAdminAdTemplateInput(req.GetUserId(), req.GetName(), req.GetVastTagUrl(), req.GetAdFormat(), duration); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	user, err := s.userRepository.GetByID(ctx, strings.TrimSpace(req.GetUserId()))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	item, err := s.adTemplateRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	item.UserID = user.ID
	item.Name = strings.TrimSpace(req.GetName())
	item.Description = nullableTrimmedStringPtr(req.Description)
	item.VastTagURL = strings.TrimSpace(req.GetVastTagUrl())
	item.AdFormat = model.StringPtr(normalizeAdFormat(req.GetAdFormat()))
	item.Duration = duration
	item.IsActive = model.BoolPtr(req.GetIsActive())
	item.IsDefault = req.GetIsDefault()
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.adTemplateRepository.SaveWithDefault(ctx, item.UserID, item); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	payload, err := s.buildAdminAdTemplate(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}
	return &appv1.UpdateAdminAdTemplateResponse{Template: payload}, nil
}
func (s *appServices) DeleteAdminAdTemplate(ctx context.Context, req *appv1.DeleteAdminAdTemplateRequest) (*appv1.MessageResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Ad template not found")
	}

	err := s.adTemplateRepository.DeleteByIDAndClearVideos(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to delete ad template")
	}
	return &appv1.MessageResponse{Message: "Ad template deleted"}, nil
}

func (s *appServices) ListAdminPlayerConfigs(ctx context.Context, req *appv1.ListAdminPlayerConfigsRequest) (*appv1.ListAdminPlayerConfigsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	search := strings.TrimSpace(protoStringValue(req.Search))
	userID := strings.TrimSpace(protoStringValue(req.UserId))

	configs, total, err := s.playerConfigRepo.ListForAdmin(ctx, search, userID, limit, offset)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to list player configs")
	}

	items := make([]*appv1.AdminPlayerConfig, 0, len(configs))
	for i := range configs {
		payload, err := s.buildAdminPlayerConfig(ctx, &configs[i])
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list player configs")
		}
		items = append(items, payload)
	}

	return &appv1.ListAdminPlayerConfigsResponse{
		Configs: items,
		Total:   total,
		Page:    page,
		Limit:   limit,
	}, nil
}

func (s *appServices) GetAdminPlayerConfig(ctx context.Context, req *appv1.GetAdminPlayerConfigRequest) (*appv1.GetAdminPlayerConfigResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	item, err := s.playerConfigRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load player config")
	}

	payload, err := s.buildAdminPlayerConfig(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load player config")
	}
	return &appv1.GetAdminPlayerConfigResponse{Config: payload}, nil
}

func (s *appServices) CreateAdminPlayerConfig(ctx context.Context, req *appv1.CreateAdminPlayerConfigRequest) (*appv1.CreateAdminPlayerConfigResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	if msg := validateAdminPlayerConfigInput(req.GetUserId(), req.GetName()); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	user, err := s.userRepository.GetByID(ctx, strings.TrimSpace(req.GetUserId()))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	item := &model.PlayerConfig{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		Name:          strings.TrimSpace(req.GetName()),
		Description:   nullableTrimmedStringPtr(req.Description),
		Autoplay:      req.GetAutoplay(),
		Loop:          req.GetLoop(),
		Muted:         req.GetMuted(),
		ShowControls:  model.BoolPtr(req.GetShowControls()),
		Pip:           model.BoolPtr(req.GetPip()),
		Airplay:       model.BoolPtr(req.GetAirplay()),
		Chromecast:    model.BoolPtr(req.GetChromecast()),
		IsActive:      model.BoolPtr(req.GetIsActive()),
		IsDefault:     req.GetIsDefault(),
		EncrytionM3u8: model.BoolPtr(req.EncrytionM3U8 == nil || *req.EncrytionM3U8),
		LogoURL:       nullableTrimmedStringPtr(req.LogoUrl),
	}
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.playerConfigRepo.CreateWithDefault(ctx, item.UserID, item); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	payload, err := s.buildAdminPlayerConfig(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &appv1.CreateAdminPlayerConfigResponse{Config: payload}, nil
}

func (s *appServices) UpdateAdminPlayerConfig(ctx context.Context, req *appv1.UpdateAdminPlayerConfigRequest) (*appv1.UpdateAdminPlayerConfigResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	if msg := validateAdminPlayerConfigInput(req.GetUserId(), req.GetName()); msg != "" {
		return nil, status.Error(codes.InvalidArgument, msg)
	}

	user, err := s.userRepository.GetByID(ctx, strings.TrimSpace(req.GetUserId()))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	item, err := s.playerConfigRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Player config not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	item.UserID = user.ID
	item.Name = strings.TrimSpace(req.GetName())
	item.Description = nullableTrimmedStringPtr(req.Description)
	item.Autoplay = req.GetAutoplay()
	item.Loop = req.GetLoop()
	item.Muted = req.GetMuted()
	item.ShowControls = model.BoolPtr(req.GetShowControls())
	item.Pip = model.BoolPtr(req.GetPip())
	item.Airplay = model.BoolPtr(req.GetAirplay())
	item.Chromecast = model.BoolPtr(req.GetChromecast())
	item.IsActive = model.BoolPtr(req.GetIsActive())
	item.IsDefault = req.GetIsDefault()
	if req.EncrytionM3U8 != nil {
		item.EncrytionM3u8 = model.BoolPtr(*req.EncrytionM3U8)
	}
	if req.LogoUrl != nil {
		item.LogoURL = nullableTrimmedStringPtr(req.LogoUrl)
	}
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.playerConfigRepo.SaveWithDefault(ctx, item.UserID, item); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}

	payload, err := s.buildAdminPlayerConfig(ctx, item)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save player config")
	}
	return &appv1.UpdateAdminPlayerConfigResponse{Config: payload}, nil
}

func (s *appServices) DeleteAdminPlayerConfig(ctx context.Context, req *appv1.DeleteAdminPlayerConfigRequest) (*appv1.MessageResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	rowsAffected, err := s.playerConfigRepo.DeleteByID(ctx, id)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete player config")
	}
	if rowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "Player config not found")
	}

	return &appv1.MessageResponse{Message: "Player config deleted"}, nil
}
