package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func (s *appServices) ListAdminPayments(ctx context.Context, req *appv1.ListAdminPaymentsRequest) (*appv1.ListAdminPaymentsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	limitInt := int(limit)
	userID := strings.TrimSpace(req.GetUserId())
	statusFilter := strings.TrimSpace(req.GetStatus())

	db := s.db.WithContext(ctx).Model(&model.Payment{})
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if statusFilter != "" {
		db = db.Where("UPPER(status) = ?", strings.ToUpper(statusFilter))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list payments")
	}

	var payments []model.Payment
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&payments).Error; err != nil {
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

	var payment model.Payment
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&payment).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Payment not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get payment")
	}

	payload, err := s.buildAdminPayment(ctx, &payment)
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

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}

	var planRecord model.Plan
	if err := s.db.WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}

	totalAmount := planRecord.Price * float64(req.GetTermMonths())
	statusValue := "SUCCESS"
	provider := "INTERNAL"
	currency := normalizeCurrency(nil)
	transactionID := buildTransactionID("sub")
	now := time.Now().UTC()

	paymentRecord := &model.Payment{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		PlanID:        &planRecord.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &statusValue,
		Provider:      &provider,
		TransactionID: &transactionID,
	}
	invoiceID := buildInvoiceID(paymentRecord.ID)
	var subscription *model.PlanSubscription
	var walletBalance float64

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(ctx, tx, user.ID); err != nil {
			return err
		}

		currentSubscription, err := model.GetLatestPlanSubscription(ctx, tx, user.ID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		baseExpiry := now
		if currentSubscription != nil && currentSubscription.ExpiresAt.After(baseExpiry) {
			baseExpiry = currentSubscription.ExpiresAt.UTC()
		}
		newExpiry := baseExpiry.AddDate(0, int(req.GetTermMonths()), 0)

		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		shortfall := maxFloat(totalAmount-currentWalletBalance, 0)
		if paymentMethod == paymentMethodWallet && shortfall > 0 {
			return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Insufficient wallet balance", map[string]interface{}{
				"payment_method": paymentMethod,
				"wallet_balance": currentWalletBalance,
				"total_amount":   totalAmount,
				"shortfall":      shortfall,
			})
		}

		topupAmount := 0.0
		if paymentMethod == paymentMethodTopup {
			if req.TopupAmount == nil {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount is required when payment method is topup", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
				})
			}
			topupAmount = maxFloat(req.GetTopupAmount(), 0)
			if topupAmount <= 0 {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than 0", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
				})
			}
			if topupAmount < shortfall {
				return statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than or equal to the required shortfall", map[string]interface{}{
					"payment_method": paymentMethod,
					"wallet_balance": currentWalletBalance,
					"total_amount":   totalAmount,
					"shortfall":      shortfall,
					"topup_amount":   topupAmount,
				})
			}
		}

		if err := tx.Create(paymentRecord).Error; err != nil {
			return err
		}

		walletUsedAmount := totalAmount
		if paymentMethod == paymentMethodTopup {
			topupTransaction := &model.WalletTransaction{
				ID:         uuid.New().String(),
				UserID:     user.ID,
				Type:       walletTransactionTypeTopup,
				Amount:     maxFloat(req.GetTopupAmount(), 0),
				Currency:   model.StringPtr(currency),
				Note:       model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", planRecord.Name, req.GetTermMonths())),
				PaymentID:  &paymentRecord.ID,
				PlanID:     &planRecord.ID,
				TermMonths: int32Ptr(req.GetTermMonths()),
			}
			if err := tx.Create(topupTransaction).Error; err != nil {
				return err
			}
		}

		debitTransaction := &model.WalletTransaction{
			ID:         uuid.New().String(),
			UserID:     user.ID,
			Type:       walletTransactionTypeSubscriptionDebit,
			Amount:     -totalAmount,
			Currency:   model.StringPtr(currency),
			Note:       model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", planRecord.Name, req.GetTermMonths())),
			PaymentID:  &paymentRecord.ID,
			PlanID:     &planRecord.ID,
			TermMonths: int32Ptr(req.GetTermMonths()),
		}
		if err := tx.Create(debitTransaction).Error; err != nil {
			return err
		}

		subscription = &model.PlanSubscription{
			ID:            uuid.New().String(),
			UserID:        user.ID,
			PaymentID:     paymentRecord.ID,
			PlanID:        planRecord.ID,
			TermMonths:    req.GetTermMonths(),
			PaymentMethod: paymentMethod,
			WalletAmount:  walletUsedAmount,
			TopupAmount:   maxFloat(req.GetTopupAmount(), 0),
			StartedAt:     now,
			ExpiresAt:     newExpiry,
		}
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Update("plan_id", planRecord.ID).Error; err != nil {
			return err
		}

		notification := buildSubscriptionNotification(user.ID, paymentRecord.ID, invoiceID, &planRecord, subscription)
		if err := tx.Create(notification).Error; err != nil {
			return err
		}

		walletBalance, err = model.GetWalletBalance(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}

	payload, err := s.buildAdminPayment(ctx, paymentRecord)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	return &appv1.CreateAdminPaymentResponse{
		Payment:       payload,
		Subscription:  toProtoPlanSubscription(subscription),
		WalletBalance: walletBalance,
		InvoiceId:     invoiceID,
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

	var payment model.Payment
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&payment).Error; err != nil {
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
		if err := s.db.WithContext(ctx).Save(&payment).Error; err != nil {
			return nil, status.Error(codes.Internal, "Failed to update payment")
		}
	}

	payload, err := s.buildAdminPayment(ctx, &payment)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update payment")
	}
	return &appv1.UpdateAdminPaymentResponse{Payment: payload}, nil
}
func (s *appServices) ListAdminPlans(ctx context.Context, _ *appv1.ListAdminPlansRequest) (*appv1.ListAdminPlansResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	var plans []model.Plan
	if err := s.db.WithContext(ctx).Order("price ASC").Find(&plans).Error; err != nil {
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

	if err := s.db.WithContext(ctx).Create(plan).Error; err != nil {
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

	var plan model.Plan
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&plan).Error; err != nil {
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

	if err := s.db.WithContext(ctx).Save(&plan).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to update plan")
	}

	payload, err := s.buildAdminPlan(ctx, &plan)
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

	var plan model.Plan
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}

	var paymentCount int64
	if err := s.db.WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", id).Count(&paymentCount).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	var subscriptionCount int64
	if err := s.db.WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", id).Count(&subscriptionCount).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}

	if paymentCount > 0 || subscriptionCount > 0 {
		inactive := false
		if err := s.db.WithContext(ctx).Model(&model.Plan{}).Where("id = ?", id).Update("is_active", inactive).Error; err != nil {
			return nil, status.Error(codes.Internal, "Failed to deactivate plan")
		}
		return &appv1.DeleteAdminPlanResponse{Message: "Plan deactivated", Mode: "deactivated"}, nil
	}

	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Plan{}).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete plan")
	}
	return &appv1.DeleteAdminPlanResponse{Message: "Plan deleted", Mode: "deleted"}, nil
}
func (s *appServices) ListAdminAdTemplates(ctx context.Context, req *appv1.ListAdminAdTemplatesRequest) (*appv1.ListAdminAdTemplatesResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	limitInt := int(limit)
	search := strings.TrimSpace(protoStringValue(req.Search))
	userID := strings.TrimSpace(protoStringValue(req.UserId))

	db := s.db.WithContext(ctx).Model(&model.AdTemplate{})
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

	var item model.AdTemplate
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load ad template")
	}

	payload, err := s.buildAdminAdTemplate(ctx, &item)
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

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.GetUserId())).First(&user).Error; err != nil {
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
		AdFormat:    model.StringPtr(normalizeAdminAdFormatValue(req.GetAdFormat())),
		Duration:    duration,
		IsActive:    model.BoolPtr(req.GetIsActive()),
		IsDefault:   req.GetIsDefault(),
	}
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := s.unsetAdminDefaultTemplates(ctx, tx, item.UserID, ""); err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	}); err != nil {
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

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", strings.TrimSpace(req.GetUserId())).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	var item model.AdTemplate
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	item.UserID = user.ID
	item.Name = strings.TrimSpace(req.GetName())
	item.Description = nullableTrimmedStringPtr(req.Description)
	item.VastTagURL = strings.TrimSpace(req.GetVastTagUrl())
	item.AdFormat = model.StringPtr(normalizeAdminAdFormatValue(req.GetAdFormat()))
	item.Duration = duration
	item.IsActive = model.BoolPtr(req.GetIsActive())
	item.IsDefault = req.GetIsDefault()
	if !boolValue(item.IsActive) {
		item.IsDefault = false
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := s.unsetAdminDefaultTemplates(ctx, tx, item.UserID, item.ID); err != nil {
				return err
			}
		}
		return tx.Save(&item).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to save ad template")
	}

	payload, err := s.buildAdminAdTemplate(ctx, &item)
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

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("ad_template_id = ?", id).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		res := tx.Where("id = ?", id).Delete(&model.AdTemplate{})
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
			return nil, status.Error(codes.NotFound, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to delete ad template")
	}
	return &appv1.MessageResponse{Message: "Ad template deleted"}, nil
}
