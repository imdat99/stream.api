package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/dto"
	"stream.api/internal/middleware"
)

func (s *appServices) requireAdmin(ctx context.Context) (*middleware.AuthResult, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if result.User == nil || result.User.Role == nil || strings.ToUpper(strings.TrimSpace(*result.User.Role)) != "ADMIN" {
		return nil, status.Error(codes.PermissionDenied, "Admin access required")
	}
	return result, nil
}

func (s *appServices) ensurePlanExists(ctx context.Context, planID *string) error {
	if planID == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*planID)
	if trimmed == "" {
		return nil
	}
	if _, err := s.planRepository.GetByID(ctx, trimmed); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Error(codes.InvalidArgument, "Plan not found")
		}
		return status.Error(codes.Internal, "Failed to validate plan")
	}
	return nil
}

func adminPageLimitOffset(pageValue int32, limitValue int32) (int32, int32, int) {
	page := pageValue
	if page < 1 {
		page = 1
	}
	limit := limitValue
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := int((page - 1) * limit)
	return page, limit, offset
}

func buildAdminJob(job *model.Job) *appv1.AdminJob {
	if job == nil {
		return nil
	}
	agentID := strconv.FormatInt(*job.AgentID, 10)
	return &appv1.AdminJob{
		Id:            job.ID,
		Status:        string(*job.Status),
		Priority:      int32(*job.Priority),
		UserId:        *job.UserID,
		Name:          job.ID,
		TimeLimit:     *job.TimeLimit,
		InputUrl:      *job.InputURL,
		OutputUrl:     *job.OutputURL,
		TotalDuration: *job.TotalDuration,
		CurrentTime:   *job.CurrentTime,
		Progress:      *job.Progress,
		AgentId:       &agentID,
		Logs:          *job.Logs,
		Config:        *job.Config,
		Cancelled:     *job.Cancelled,
		RetryCount:    int32(*job.RetryCount),
		MaxRetries:    int32(*job.MaxRetries),
		CreatedAt:     timestamppb.New(*job.CreatedAt),
		UpdatedAt:     timestamppb.New(*job.UpdatedAt),
		VideoId:       stringPointerOrNil(*job.VideoID),
	}
}

func buildAdminAgent(agent *dto.AgentWithStats) *appv1.AdminAgent {
	if agent == nil || agent.Agent == nil {
		return nil
	}
	return &appv1.AdminAgent{
		Id:            agent.ID,
		Name:          agent.Name,
		Platform:      agent.Platform,
		Backend:       agent.Backend,
		Version:       agent.Version,
		Capacity:      agent.Capacity,
		Status:        string(agent.Status),
		Cpu:           agent.CPU,
		Ram:           agent.RAM,
		LastHeartbeat: timestamppb.New(agent.LastHeartbeat),
		CreatedAt:     timestamppb.New(agent.CreatedAt),
		UpdatedAt:     timestamppb.New(agent.UpdatedAt),
	}
}

func normalizeAdminRoleValue(value string) string {
	role := strings.ToUpper(strings.TrimSpace(value))
	if role == "" {
		return "USER"
	}
	return role
}

func isValidAdminRoleValue(role string) bool {
	switch normalizeAdminRoleValue(role) {
	case "USER", "ADMIN", "BLOCK":
		return true
	default:
		return false
	}
}

func (s *appServices) buildAdminUser(ctx context.Context, user *model.User) (*appv1.AdminUser, error) {
	if user == nil {
		return nil, nil
	}

	payload := &appv1.AdminUser{
		Id:            user.ID,
		Email:         user.Email,
		Username:      nullableTrimmedString(user.Username),
		Avatar:        nullableTrimmedString(user.Avatar),
		Role:          nullableTrimmedString(user.Role),
		PlanId:        nullableTrimmedString(user.PlanID),
		StorageUsed:   user.StorageUsed,
		CreatedAt:     timeToProto(user.CreatedAt),
		UpdatedAt:     timestamppb.New(user.UpdatedAt.UTC()),
		WalletBalance: 0,
	}

	videoCount, err := s.loadAdminUserVideoCount(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	payload.VideoCount = videoCount

	walletBalance, err := s.billingRepository.GetWalletBalance(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	payload.WalletBalance = walletBalance

	planName, err := s.loadAdminPlanName(ctx, user.PlanID)
	if err != nil {
		return nil, err
	}
	payload.PlanName = planName

	return payload, nil
}

func (s *appServices) buildAdminUserDetail(ctx context.Context, user *model.User, subscription *model.PlanSubscription) (*appv1.AdminUserDetail, error) {
	payload, err := s.buildAdminUser(ctx, user)
	if err != nil {
		return nil, err
	}
	referral, err := s.buildAdminUserReferralInfo(ctx, user)
	if err != nil {
		return nil, err
	}
	return &appv1.AdminUserDetail{
		User:         payload,
		Subscription: toProtoPlanSubscription(subscription),
		Referral:     referral,
	}, nil
}

func (s *appServices) buildAdminUserReferralInfo(ctx context.Context, user *model.User) (*appv1.AdminUserReferralInfo, error) {
	if user == nil {
		return nil, nil
	}

	var referrer *appv1.ReferralUserSummary
	if user.ReferredByUserID != nil && strings.TrimSpace(*user.ReferredByUserID) != "" {
		loadedReferrer, err := s.loadReferralUserSummary(ctx, strings.TrimSpace(*user.ReferredByUserID))
		if err != nil {
			return nil, err
		}
		referrer = loadedReferrer
	}

	bps := effectiveReferralRewardBps(user.ReferralRewardBps)
	referral := &appv1.AdminUserReferralInfo{
		Referrer:               referrer,
		ReferralEligible:       referralUserEligible(user),
		EffectiveRewardPercent: referralRewardBpsToPercent(bps),
		RewardOverridePercent: func() *float64 {
			if user.ReferralRewardBps == nil {
				return nil
			}
			value := referralRewardBpsToPercent(*user.ReferralRewardBps)
			return &value
		}(),
		ShareLink:       s.buildReferralShareLink(user.Username),
		RewardGranted:   referralRewardProcessed(user),
		RewardGrantedAt: timeToProto(user.ReferralRewardGrantedAt),
		RewardPaymentId: nullableTrimmedString(user.ReferralRewardPaymentID),
		RewardAmount:    user.ReferralRewardAmount,
	}
	return referral, nil
}

func (s *appServices) buildAdminVideo(ctx context.Context, video *model.Video) (*appv1.AdminVideo, error) {
	if video == nil {
		return nil, nil
	}

	statusValue := stringValue(video.Status)
	if statusValue == "" {
		statusValue = "ready"
	}
	jobID, err := s.loadLatestVideoJobID(ctx, video.ID)
	if err != nil {
		return nil, err
	}

	payload := &appv1.AdminVideo{
		Id:               video.ID,
		UserId:           video.UserID,
		Title:            video.Title,
		Description:      nullableTrimmedString(video.Description),
		Url:              video.URL,
		Status:           strings.ToLower(statusValue),
		Size:             video.Size,
		Duration:         video.Duration,
		Format:           video.Format,
		CreatedAt:        timeToProto(video.CreatedAt),
		UpdatedAt:        timestamppb.New(video.UpdatedAt.UTC()),
		ProcessingStatus: nullableTrimmedString(video.ProcessingStatus),
		JobId:            jobID,
	}

	ownerEmail, err := s.loadAdminUserEmail(ctx, video.UserID)
	if err != nil {
		return nil, err
	}
	payload.OwnerEmail = ownerEmail

	adTemplateID, adTemplateName, err := s.loadAdminVideoAdTemplateDetails(ctx, video)
	if err != nil {
		return nil, err
	}
	payload.AdTemplateId = adTemplateID
	payload.AdTemplateName = adTemplateName

	return payload, nil
}

func (s *appServices) buildAdminPayment(ctx context.Context, payment *model.Payment) (*appv1.AdminPayment, error) {
	if payment == nil {
		return nil, nil
	}

	payload := &appv1.AdminPayment{
		Id:            payment.ID,
		UserId:        payment.UserID,
		PlanId:        nullableTrimmedString(payment.PlanID),
		Amount:        payment.Amount,
		Currency:      normalizeCurrency(payment.Currency),
		Status:        normalizePaymentStatus(payment.Status),
		Provider:      strings.ToUpper(stringValue(payment.Provider)),
		TransactionId: nullableTrimmedString(payment.TransactionID),
		InvoiceId:     payment.ID,
		CreatedAt:     timeToProto(payment.CreatedAt),
		UpdatedAt:     timestamppb.New(payment.UpdatedAt.UTC()),
	}

	userEmail, err := s.loadAdminUserEmail(ctx, payment.UserID)
	if err != nil {
		return nil, err
	}
	payload.UserEmail = userEmail

	planName, err := s.loadAdminPlanName(ctx, payment.PlanID)
	if err != nil {
		return nil, err
	}
	payload.PlanName = planName

	termMonths, paymentMethod, expiresAt, walletAmount, topupAmount, err := s.loadAdminPaymentSubscriptionDetails(ctx, payment.ID)
	if err != nil {
		return nil, err
	}
	payload.TermMonths = termMonths
	payload.PaymentMethod = paymentMethod
	payload.ExpiresAt = expiresAt
	payload.WalletAmount = walletAmount
	payload.TopupAmount = topupAmount

	return payload, nil
}

func (s *appServices) loadAdminUserVideoCount(ctx context.Context, userID string) (int64, error) {
	return s.videoRepository.CountByUser(ctx, userID)
}

func (s *appServices) loadAdminUserEmail(ctx context.Context, userID string) (*string, error) {
	email, err := s.userRepository.GetEmailByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return nullableTrimmedString(email), nil
}

func (s *appServices) loadReferralUserSummary(ctx context.Context, userID string) (*appv1.ReferralUserSummary, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, nil
	}
	user, err := s.userRepository.GetReferralSummaryByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &appv1.ReferralUserSummary{
		Id:       user.ID,
		Email:    user.Email,
		Username: nullableTrimmedString(user.Username),
	}, nil
}

func (s *appServices) loadAdminPlanName(ctx context.Context, planID *string) (*string, error) {
	if planID == nil || strings.TrimSpace(*planID) == "" {
		return nil, nil
	}
	plan, err := s.planRepository.GetByID(ctx, *planID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return nullableTrimmedString(&plan.Name), nil
}

func (s *appServices) loadAdminVideoAdTemplateDetails(ctx context.Context, video *model.Video) (*string, *string, error) {
	if video == nil {
		return nil, nil, nil
	}
	adTemplateID := nullableTrimmedString(video.AdID)
	if adTemplateID == nil {
		return nil, nil, nil
	}
	adTemplateName, err := s.loadAdminAdTemplateName(ctx, *adTemplateID)
	if err != nil {
		return nil, nil, err
	}
	return adTemplateID, adTemplateName, nil
}

func (s *appServices) loadAdminAdTemplateName(ctx context.Context, adTemplateID string) (*string, error) {
	template, err := s.adTemplateRepository.GetByID(ctx, adTemplateID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return nullableTrimmedString(&template.Name), nil
}

func (s *appServices) loadLatestVideoJobID(ctx context.Context, videoID string) (*string, error) {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" {
		return nil, nil
	}

	job, err := s.jobRepository.GetLatestByVideoID(ctx, videoID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return stringPointerOrNil(job.ID), nil
}

func (s *appServices) loadAdminPaymentSubscriptionDetails(ctx context.Context, paymentID string) (*int32, *string, *string, *float64, *float64, error) {
	subscription, err := s.paymentRepository.GetSubscriptionByPaymentID(ctx, paymentID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil, nil, nil, nil
		}
		return nil, nil, nil, nil, nil, err
	}
	termMonths := subscription.TermMonths
	paymentMethod := nullableTrimmedString(&subscription.PaymentMethod)
	expiresAt := subscription.ExpiresAt.UTC().Format(time.RFC3339)
	walletAmount := subscription.WalletAmount
	topupAmount := subscription.TopupAmount
	return &termMonths, paymentMethod, nullableTrimmedString(&expiresAt), &walletAmount, &topupAmount, nil
}

func (s *appServices) loadAdminPlanUsageCounts(ctx context.Context, planID string) (int64, int64, int64, error) {
	userCount, err := s.userRepository.CountByPlanID(ctx, planID)
	if err != nil {
		return 0, 0, 0, err
	}

	paymentCount, err := s.paymentRepository.CountByPlanID(ctx, planID)
	if err != nil {
		return 0, 0, 0, err
	}

	subscriptionCount, err := s.planRepository.CountSubscriptionsByPlan(ctx, planID)
	if err != nil {
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

func validateAdminAdTemplateInput(userID, name, vastTagURL, adFormat string, duration *int64) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(vastTagURL) == "" {
		return "Name and VAST URL are required"
	}
	format := normalizeAdFormat(adFormat)
	if format == "mid-roll" && (duration == nil || *duration <= 0) {
		return "Duration is required for mid-roll templates"
	}
	return ""
}

func validateAdminPopupAdInput(userID, popupType, label, value string, maxTriggersPerSession *int32) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	popupType = strings.ToLower(strings.TrimSpace(popupType))
	if popupType != "url" && popupType != "script" {
		return "Popup ad type must be url or script"
	}
	if strings.TrimSpace(label) == "" || strings.TrimSpace(value) == "" {
		return "Label and value are required"
	}
	if maxTriggersPerSession != nil && *maxTriggersPerSession < 1 {
		return "Max triggers per session must be greater than 0"
	}
	return ""
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

func (s *appServices) buildAdminPlan(ctx context.Context, plan *model.Plan) (*appv1.AdminPlan, error) {
	if plan == nil {
		return nil, nil
	}

	userCount, paymentCount, subscriptionCount, err := s.loadAdminPlanUsageCounts(ctx, plan.ID)
	if err != nil {
		return nil, err
	}

	payload := &appv1.AdminPlan{
		Id:                plan.ID,
		Name:              plan.Name,
		Description:       nullableTrimmedString(plan.Description),
		Features:          append([]string(nil), plan.Features...),
		Price:             plan.Price,
		Cycle:             plan.Cycle,
		StorageLimit:      plan.StorageLimit,
		UploadLimit:       plan.UploadLimit,
		DurationLimit:     plan.DurationLimit,
		QualityLimit:      plan.QualityLimit,
		IsActive:          boolValue(plan.IsActive),
		UserCount:         userCount,
		PaymentCount:      paymentCount,
		SubscriptionCount: subscriptionCount,
	}
	return payload, nil
}

func (s *appServices) buildAdminPopupAd(ctx context.Context, item *model.PopupAd) (*appv1.AdminPopupAd, error) {
	if item == nil {
		return nil, nil
	}

	payload := &appv1.AdminPopupAd{
		Id:                   item.ID,
		UserId:               item.UserID,
		Type:                 item.Type,
		Label:                item.Label,
		Value:                item.Value,
		IsActive:             boolValue(item.IsActive),
		MaxTriggersPerSession: func() int32 { if item.MaxTriggersPerSession != nil { return *item.MaxTriggersPerSession }; return 0 }(),
		CreatedAt:            timeToProto(item.CreatedAt),
		UpdatedAt:            timeToProto(item.UpdatedAt),
	}

	ownerEmail, err := s.loadAdminUserEmail(ctx, item.UserID)
	if err != nil {
		return nil, err
	}
	payload.OwnerEmail = ownerEmail

	return payload, nil
}

func (s *appServices) buildAdminAdTemplate(ctx context.Context, item *model.AdTemplate) (*appv1.AdminAdTemplate, error) {
	if item == nil {
		return nil, nil
	}

	payload := &appv1.AdminAdTemplate{
		Id:          item.ID,
		UserId:      item.UserID,
		Name:        item.Name,
		Description: nullableTrimmedString(item.Description),
		VastTagUrl:  item.VastTagURL,
		AdFormat:    stringValue(item.AdFormat),
		Duration:    item.Duration,
		IsActive:    boolValue(item.IsActive),
		IsDefault:   item.IsDefault,
		CreatedAt:   timeToProto(item.CreatedAt),
		UpdatedAt:   timeToProto(item.UpdatedAt),
	}

	ownerEmail, err := s.loadAdminUserEmail(ctx, item.UserID)
	if err != nil {
		return nil, err
	}
	payload.OwnerEmail = ownerEmail

	return payload, nil
}

func (s *appServices) buildAdminPlayerConfig(ctx context.Context, item *model.PlayerConfig) (*appv1.AdminPlayerConfig, error) {
	if item == nil {
		return nil, nil
	}

	payload := &appv1.AdminPlayerConfig{
		Id:            item.ID,
		UserId:        item.UserID,
		Name:          item.Name,
		Description:   nullableTrimmedString(item.Description),
		Autoplay:      item.Autoplay,
		Loop:          item.Loop,
		Muted:         item.Muted,
		ShowControls:  boolValue(item.ShowControls),
		Pip:           boolValue(item.Pip),
		Airplay:       boolValue(item.Airplay),
		Chromecast:    boolValue(item.Chromecast),
		IsActive:      boolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(&item.UpdatedAt),
		EncrytionM3U8: boolValue(item.EncrytionM3u8),
		LogoUrl:       nullableTrimmedString(item.LogoURL),
	}

	ownerEmail, err := s.loadAdminUserEmail(ctx, item.UserID)
	if err != nil {
		return nil, err
	}
	payload.OwnerEmail = ownerEmail

	return payload, nil
}
