package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/middleware"
	"stream.api/internal/video/runtime/services"
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
func buildAdminAgent(agent *services.AgentWithStats) *appv1.AdminAgent {
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
func (s *appServices) ensurePlanExists(ctx context.Context, planID *string) error {
	if planID == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*planID)
	if trimmed == "" {
		return nil
	}
	var count int64
	if err := s.db.WithContext(ctx).Model(&model.Plan{}).Where("id = ?", trimmed).Count(&count).Error; err != nil {
		return status.Error(codes.Internal, "Failed to validate plan")
	}
	if count == 0 {
		return status.Error(codes.InvalidArgument, "Plan not found")
	}
	return nil
}
func referralUserEligible(user *model.User) bool {
	if user == nil || user.ReferralEligible == nil {
		return true
	}
	return *user.ReferralEligible
}

func effectiveReferralRewardBps(value *int32) int32 {
	if value == nil {
		return defaultReferralRewardBps
	}
	if *value < 0 {
		return 0
	}
	if *value > 10000 {
		return 10000
	}
	return *value
}

func referralRewardBpsToPercent(value int32) float64 {
	return float64(value) / 100
}

func referralRewardProcessed(user *model.User) bool {
	if user == nil {
		return false
	}
	if user.ReferralRewardGrantedAt != nil {
		return true
	}
	if user.ReferralRewardPaymentID != nil && strings.TrimSpace(*user.ReferralRewardPaymentID) != "" {
		return true
	}
	return false
}

func sameTrimmedStringFold(left *string, right string) bool {
	if left == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(*left), strings.TrimSpace(right))
}

func (s *appServices) buildReferralShareLink(username *string) *string {
	trimmed := strings.TrimSpace(stringValue(username))
	if trimmed == "" {
		return nil
	}
	path := "/ref/" + url.PathEscape(trimmed)
	base := strings.TrimRight(strings.TrimSpace(s.frontendBaseURL), "/")
	if base == "" {
		return &path
	}
	link := base + path
	return &link
}

func (s *appServices) loadReferralUsersByUsername(ctx context.Context, username string) ([]model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil, nil
	}
	var users []model.User
	if err := s.db.WithContext(ctx).
		Where("LOWER(username) = LOWER(?)", trimmed).
		Order("created_at ASC, id ASC").
		Limit(2).
		Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (s *appServices) resolveReferralUserByUsername(ctx context.Context, username string) (*model.User, error) {
	users, err := s.loadReferralUsersByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, nil
	}
	return &users[0], nil
}

func (s *appServices) loadReferralUserByUsernameStrict(ctx context.Context, username string) (*model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil, status.Error(codes.InvalidArgument, "Referral username is required")
	}
	users, err := s.loadReferralUsersByUsername(ctx, trimmed)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to resolve referral user")
	}
	if len(users) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Referral user not found")
	}
	if len(users) > 1 {
		return nil, status.Error(codes.InvalidArgument, "Referral username is ambiguous")
	}
	return &users[0], nil
}

func (s *appServices) resolveSignupReferrerID(ctx context.Context, refUsername string, newUsername string) (*string, error) {
	trimmedRefUsername := strings.TrimSpace(refUsername)
	if trimmedRefUsername == "" || strings.EqualFold(trimmedRefUsername, strings.TrimSpace(newUsername)) {
		return nil, nil
	}
	referrer, err := s.resolveReferralUserByUsername(ctx, trimmedRefUsername)
	if err != nil {
		return nil, err
	}
	if referrer == nil {
		return nil, nil
	}
	return &referrer.ID, nil
}
func (s *appServices) saveAdminVideoAdConfig(ctx context.Context, tx *gorm.DB, video *model.Video, userID string, adTemplateID *string) error {
	if video == nil || adTemplateID == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*adTemplateID)
	if trimmed == "" {
		if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", nil).Error; err != nil {
			return err
		}
		video.AdID = nil
		return nil
	}

	var template model.AdTemplate
	if err := tx.WithContext(ctx).Select("id").Where("id = ? AND user_id = ?", trimmed, userID).First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("Ad template not found")
		}
		return err
	}

	if err := tx.WithContext(ctx).Model(&model.Video{}).Where("id = ?", video.ID).Update("ad_id", template.ID).Error; err != nil {
		return err
	}
	video.AdID = &template.ID
	return nil
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

	walletBalance, err := model.GetWalletBalance(ctx, s.db, user.ID)
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
	var videoCount int64
	if err := s.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", userID).Count(&videoCount).Error; err != nil {
		return 0, err
	}
	return videoCount, nil
}

func (s *appServices) loadAdminUserEmail(ctx context.Context, userID string) (*string, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Select("id, email").Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return nullableTrimmedString(&user.Email), nil
}

func (s *appServices) loadReferralUserSummary(ctx context.Context, userID string) (*appv1.ReferralUserSummary, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, nil
	}
	var user model.User
	if err := s.db.WithContext(ctx).Select("id, email, username").Where("id = ?", userID).First(&user).Error; err != nil {
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
	var plan model.Plan
	if err := s.db.WithContext(ctx).Select("id, name").Where("id = ?", *planID).First(&plan).Error; err != nil {
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
	var template model.AdTemplate
	if err := s.db.WithContext(ctx).Select("id, name").Where("id = ?", adTemplateID).First(&template).Error; err != nil {
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

	var job model.Job
	if err := s.db.WithContext(ctx).
		Where("config::jsonb ->> 'video_id' = ?", videoID).
		Order("created_at DESC").
		First(&job).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return stringPointerOrNil(job.ID), nil
}

func (s *appServices) loadAdminPaymentSubscriptionDetails(ctx context.Context, paymentID string) (*int32, *string, *string, *float64, *float64, error) {
	var subscription model.PlanSubscription
	if err := s.db.WithContext(ctx).Where("payment_id = ?", paymentID).Order("created_at DESC").First(&subscription).Error; err != nil {
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
	var userCount int64
	if err := s.db.WithContext(ctx).Model(&model.User{}).Where("plan_id = ?", planID).Count(&userCount).Error; err != nil {
		return 0, 0, 0, err
	}

	var paymentCount int64
	if err := s.db.WithContext(ctx).Model(&model.Payment{}).Where("plan_id = ?", planID).Count(&paymentCount).Error; err != nil {
		return 0, 0, 0, err
	}

	var subscriptionCount int64
	if err := s.db.WithContext(ctx).Model(&model.PlanSubscription{}).Where("plan_id = ?", planID).Count(&subscriptionCount).Error; err != nil {
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
func validateAdminPlayerConfigInput(userID, name string) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(name) == "" {
		return "Name is required"
	}
	return ""
}
func (s *appServices) unsetAdminDefaultTemplates(ctx context.Context, tx *gorm.DB, userID, excludeID string) error {
	query := tx.WithContext(ctx).Model(&model.AdTemplate{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}
func (s *appServices) unsetAdminDefaultPlayerConfigs(ctx context.Context, tx *gorm.DB, userID, excludeID string) error {
	query := tx.WithContext(ctx).Model(&model.PlayerConfig{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
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
func (s *appServices) authenticate(ctx context.Context) (*middleware.AuthResult, error) {
	return s.authenticator.Authenticate(ctx)
}
func statusErrorWithBody(ctx context.Context, grpcCode codes.Code, httpCode int, message string, data any) error {
	body := apiErrorBody{
		Code:    httpCode,
		Message: message,
		Data:    data,
	}
	encoded, err := json.Marshal(body)
	if err == nil {
		_ = grpc.SetTrailer(ctx, metadata.Pairs("x-error-body", string(encoded)))
	}
	return status.Error(grpcCode, message)
}

func (s *appServices) loadPaymentPlanForUser(ctx context.Context, planID string) (*model.Plan, error) {
	var planRecord model.Plan
	if err := s.db.WithContext(ctx).Where("id = ?", planID).First(&planRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Plan not found")
		}
		s.logger.Error("Failed to load plan", "error", err)
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	if planRecord.IsActive == nil || !*planRecord.IsActive {
		return nil, status.Error(codes.InvalidArgument, "Plan is not active")
	}
	return &planRecord, nil
}

func (s *appServices) loadPaymentPlanForAdmin(ctx context.Context, planID string) (*model.Plan, error) {
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
	return &planRecord, nil
}

func (s *appServices) loadPaymentUserForAdmin(ctx context.Context, userID string) (*model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to create payment")
	}
	return &user, nil
}

func (s *appServices) executePaymentFlow(ctx context.Context, input paymentExecutionInput) (*paymentExecutionResult, error) {
	totalAmount := input.Plan.Price * float64(input.TermMonths)
	if totalAmount < 0 {
		return nil, status.Error(codes.InvalidArgument, "Amount must be greater than or equal to 0")
	}

	statusValue := "SUCCESS"
	provider := "INTERNAL"
	currency := normalizeCurrency(nil)
	transactionID := buildTransactionID("sub")
	now := time.Now().UTC()
	paymentRecord := &model.Payment{
		ID:            uuid.New().String(),
		UserID:        input.UserID,
		PlanID:        &input.Plan.ID,
		Amount:        totalAmount,
		Currency:      &currency,
		Status:        &statusValue,
		Provider:      &provider,
		TransactionID: &transactionID,
	}
	invoiceID := buildInvoiceID(paymentRecord.ID)

	result := &paymentExecutionResult{
		Payment:   paymentRecord,
		InvoiceID: invoiceID,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockUserForUpdate(ctx, tx, input.UserID); err != nil {
			return err
		}

		newExpiry, err := loadPaymentExpiry(ctx, tx, input.UserID, input.TermMonths, now)
		if err != nil {
			return err
		}
		currentWalletBalance, err := model.GetWalletBalance(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		validatedTopupAmount, err := validatePaymentFunding(ctx, input, totalAmount, currentWalletBalance)
		if err != nil {
			return err
		}
		if err := tx.Create(paymentRecord).Error; err != nil {
			return err
		}
		if err := createPaymentWalletTransactions(tx, input, paymentRecord, totalAmount, validatedTopupAmount, currency); err != nil {
			return err
		}
		subscription := buildPaymentSubscription(input, paymentRecord, totalAmount, validatedTopupAmount, now, newExpiry)
		if err := tx.Create(subscription).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", input.UserID).Update("plan_id", input.Plan.ID).Error; err != nil {
			return err
		}
		notification := buildSubscriptionNotification(input.UserID, paymentRecord.ID, invoiceID, input.Plan, subscription)
		if err := tx.Create(notification).Error; err != nil {
			return err
		}
		if _, err := s.maybeGrantReferralReward(ctx, tx, input, paymentRecord, subscription); err != nil {
			return err
		}
		walletBalance, err := model.GetWalletBalance(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		result.Subscription = subscription
		result.WalletBalance = walletBalance
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func loadPaymentExpiry(ctx context.Context, tx *gorm.DB, userID string, termMonths int32, now time.Time) (time.Time, error) {
	currentSubscription, err := model.GetLatestPlanSubscription(ctx, tx, userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, err
	}
	baseExpiry := now
	if currentSubscription != nil && currentSubscription.ExpiresAt.After(baseExpiry) {
		baseExpiry = currentSubscription.ExpiresAt.UTC()
	}
	return baseExpiry.AddDate(0, int(termMonths), 0), nil
}

func validatePaymentFunding(ctx context.Context, input paymentExecutionInput, totalAmount, currentWalletBalance float64) (float64, error) {
	shortfall := maxFloat(totalAmount-currentWalletBalance, 0)
	if input.PaymentMethod == paymentMethodWallet && shortfall > 0 {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Insufficient wallet balance", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if input.PaymentMethod != paymentMethodTopup {
		return 0, nil
	}
	if input.TopupAmount == nil {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount is required when payment method is topup", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	topupAmount := maxFloat(*input.TopupAmount, 0)
	if topupAmount <= 0 {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than 0", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
		})
	}
	if topupAmount < shortfall {
		return 0, statusErrorWithBody(ctx, codes.InvalidArgument, http.StatusBadRequest, "Top-up amount must be greater than or equal to the required shortfall", map[string]any{
			"payment_method": input.PaymentMethod,
			"wallet_balance": currentWalletBalance,
			"total_amount":   totalAmount,
			"shortfall":      shortfall,
			"topup_amount":   topupAmount,
		})
	}
	return topupAmount, nil
}

func createPaymentWalletTransactions(tx *gorm.DB, input paymentExecutionInput, paymentRecord *model.Payment, totalAmount, topupAmount float64, currency string) error {
	if input.PaymentMethod == paymentMethodTopup {
		topupTransaction := &model.WalletTransaction{
			ID:         uuid.New().String(),
			UserID:     input.UserID,
			Type:       walletTransactionTypeTopup,
			Amount:     topupAmount,
			Currency:   model.StringPtr(currency),
			Note:       model.StringPtr(fmt.Sprintf("Wallet top-up for %s (%d months)", input.Plan.Name, input.TermMonths)),
			PaymentID:  &paymentRecord.ID,
			PlanID:     &input.Plan.ID,
			TermMonths: int32Ptr(input.TermMonths),
		}
		if err := tx.Create(topupTransaction).Error; err != nil {
			return err
		}
	}
	debitTransaction := &model.WalletTransaction{
		ID:         uuid.New().String(),
		UserID:     input.UserID,
		Type:       walletTransactionTypeSubscriptionDebit,
		Amount:     -totalAmount,
		Currency:   model.StringPtr(currency),
		Note:       model.StringPtr(fmt.Sprintf("Subscription payment for %s (%d months)", input.Plan.Name, input.TermMonths)),
		PaymentID:  &paymentRecord.ID,
		PlanID:     &input.Plan.ID,
		TermMonths: int32Ptr(input.TermMonths),
	}
	return tx.Create(debitTransaction).Error
}

func buildPaymentSubscription(input paymentExecutionInput, paymentRecord *model.Payment, totalAmount, topupAmount float64, now, newExpiry time.Time) *model.PlanSubscription {
	return &model.PlanSubscription{
		ID:            uuid.New().String(),
		UserID:        input.UserID,
		PaymentID:     paymentRecord.ID,
		PlanID:        input.Plan.ID,
		TermMonths:    input.TermMonths,
		PaymentMethod: input.PaymentMethod,
		WalletAmount:  totalAmount,
		TopupAmount:   topupAmount,
		StartedAt:     now,
		ExpiresAt:     newExpiry,
	}
}
func (s *appServices) issueSessionCookies(ctx context.Context, user *model.User) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	tokenPair, err := s.tokenProvider.GenerateTokenPair(user.ID, user.Email, safeRole(user.Role))
	if err != nil {
		s.logger.Error("Token generation failed", "error", err)
		return status.Error(codes.Internal, "Error generating tokens")
	}

	if err := s.cache.Set(ctx, "refresh_uuid:"+tokenPair.RefreshUUID, user.ID, time.Until(time.Unix(tokenPair.RtExpires, 0))); err != nil {
		s.logger.Error("Session storage failed", "error", err)
		return status.Error(codes.Internal, "Error storing session")
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(
		"set-cookie", buildTokenCookie("access_token", tokenPair.AccessToken, int(tokenPair.AtExpires-time.Now().Unix())),
		"set-cookie", buildTokenCookie("refresh_token", tokenPair.RefreshToken, int(tokenPair.RtExpires-time.Now().Unix())),
	)); err != nil {
		s.logger.Error("Failed to set gRPC auth headers", "error", err)
	}

	return nil
}
func buildTokenCookie(name string, value string, maxAge int) string {
	return (&http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
	}).String()
}
func messageResponse(message string) *appv1.MessageResponse {
	return &appv1.MessageResponse{Message: message}
}
func ensurePaidPlan(user *model.User) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	if user.PlanID == nil || strings.TrimSpace(*user.PlanID) == "" {
		return status.Error(codes.PermissionDenied, adTemplateUpgradeRequiredMessage)
	}
	return nil
}
func playerConfigActionAllowed(user *model.User, configCount int64, action string) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	if user.PlanID != nil && strings.TrimSpace(*user.PlanID) != "" {
		return nil
	}

	switch action {
	case "create":
		if configCount > 0 {
			return status.Error(codes.FailedPrecondition, playerConfigFreePlanLimitMessage)
		}
		return nil
	case "delete":
		return nil
	case "update", "set-default", "toggle-active":
		if configCount > 1 {
			return status.Error(codes.FailedPrecondition, playerConfigFreePlanReconciliationMessage)
		}
		return nil
	default:
		return nil
	}
}
func safeRole(role *string) string {
	if role == nil || strings.TrimSpace(*role) == "" {
		return "USER"
	}
	return *role
}
func generateOAuthState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
func googleOAuthStateCacheKey(state string) string {
	return "google_oauth_state:" + state
}
func stringPointerOrNil(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
func toProtoVideo(item *model.Video, jobID ...string) *appv1.Video {
	if item == nil {
		return nil
	}
	statusValue := stringValue(item.Status)
	if statusValue == "" {
		statusValue = "ready"
	}
	var linkedJobID *string
	if len(jobID) > 0 {
		linkedJobID = stringPointerOrNil(jobID[0])
	}
	return &appv1.Video{
		Id:               item.ID,
		UserId:           item.UserID,
		Title:            item.Title,
		Description:      item.Description,
		Url:              item.URL,
		Status:           strings.ToLower(statusValue),
		Size:             item.Size,
		Duration:         item.Duration,
		Format:           item.Format,
		Thumbnail:        item.Thumbnail,
		ProcessingStatus: item.ProcessingStatus,
		StorageType:      item.StorageType,
		CreatedAt:        timeToProto(item.CreatedAt),
		UpdatedAt:        timestamppb.New(item.UpdatedAt.UTC()),
		JobId:            linkedJobID,
	}
}

func (s *appServices) buildVideo(ctx context.Context, video *model.Video) (*appv1.Video, error) {
	if video == nil {
		return nil, nil
	}
	jobID, err := s.loadLatestVideoJobID(ctx, video.ID)
	if err != nil {
		return nil, err
	}
	if jobID != nil {
		return toProtoVideo(video, *jobID), nil
	}
	return toProtoVideo(video), nil
}

func normalizeVideoStatusValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "processing", "pending":
		return "processing"
	case "failed", "error":
		return "failed"
	default:
		return "ready"
	}
}
func detectStorageType(rawURL string) string {
	if shouldDeleteStoredObject(rawURL) {
		return "S3"
	}
	return "WORKER"
}
func shouldDeleteStoredObject(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return !strings.HasPrefix(trimmed, "/")
	}
	return parsed.Scheme == "" && parsed.Host == "" && !strings.HasPrefix(trimmed, "/")
}
func extractObjectKey(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	return strings.TrimPrefix(parsed.Path, "/")
}
func protoUserFromPayload(user *userPayload) *appv1.User {
	if user == nil {
		return nil
	}
	return &appv1.User{
		Id:                user.ID,
		Email:             user.Email,
		Username:          user.Username,
		Avatar:            user.Avatar,
		Role:              user.Role,
		GoogleId:          user.GoogleID,
		StorageUsed:       user.StorageUsed,
		PlanId:            user.PlanID,
		PlanStartedAt:     timeToProto(user.PlanStartedAt),
		PlanExpiresAt:     timeToProto(user.PlanExpiresAt),
		PlanTermMonths:    user.PlanTermMonths,
		PlanPaymentMethod: user.PlanPaymentMethod,
		PlanExpiringSoon:  user.PlanExpiringSoon,
		WalletBalance:     user.WalletBalance,
		Language:          user.Language,
		Locale:            user.Locale,
		CreatedAt:         timeToProto(user.CreatedAt),
		UpdatedAt:         timestamppb.New(user.UpdatedAt),
	}
}
func toProtoUser(user *userPayload) *appv1.User {
	return protoUserFromPayload(user)
}
func toProtoPreferences(pref *model.UserPreference) *appv1.Preferences {
	if pref == nil {
		return nil
	}
	return &appv1.Preferences{
		EmailNotifications:     boolValue(pref.EmailNotifications),
		PushNotifications:      boolValue(pref.PushNotifications),
		MarketingNotifications: pref.MarketingNotifications,
		TelegramNotifications:  pref.TelegramNotifications,
		Language:               model.StringValue(pref.Language),
		Locale:                 model.StringValue(pref.Locale),
	}
}
func toProtoNotification(item model.Notification) *appv1.Notification {
	return &appv1.Notification{
		Id:          item.ID,
		Type:        normalizeNotificationType(item.Type),
		Title:       item.Title,
		Message:     item.Message,
		Read:        item.IsRead,
		ActionUrl:   item.ActionURL,
		ActionLabel: item.ActionLabel,
		CreatedAt:   timeToProto(item.CreatedAt),
	}
}
func toProtoDomain(item *model.Domain) *appv1.Domain {
	if item == nil {
		return nil
	}
	return &appv1.Domain{
		Id:        item.ID,
		Name:      item.Name,
		CreatedAt: timeToProto(item.CreatedAt),
		UpdatedAt: timeToProto(item.UpdatedAt),
	}
}
func toProtoAdTemplate(item *model.AdTemplate) *appv1.AdTemplate {
	if item == nil {
		return nil
	}
	return &appv1.AdTemplate{
		Id:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		VastTagUrl:  item.VastTagURL,
		AdFormat:    model.StringValue(item.AdFormat),
		Duration:    int64PtrToInt32Ptr(item.Duration),
		IsActive:    boolValue(item.IsActive),
		IsDefault:   item.IsDefault,
		CreatedAt:   timeToProto(item.CreatedAt),
		UpdatedAt:   timeToProto(item.UpdatedAt),
	}
}
func toProtoPlayerConfig(item *model.PlayerConfig) *appv1.PlayerConfig {
	if item == nil {
		return nil
	}
	return &appv1.PlayerConfig{
		Id:            item.ID,
		Name:          item.Name,
		Description:   item.Description,
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
}
func toProtoAdminPlayerConfig(item *model.PlayerConfig, ownerEmail *string) *appv1.AdminPlayerConfig {
	if item == nil {
		return nil
	}
	return &appv1.AdminPlayerConfig{
		Id:            item.ID,
		UserId:        item.UserID,
		Name:          item.Name,
		Description:   item.Description,
		Autoplay:      item.Autoplay,
		Loop:          item.Loop,
		Muted:         item.Muted,
		ShowControls:  boolValue(item.ShowControls),
		Pip:           boolValue(item.Pip),
		Airplay:       boolValue(item.Airplay),
		Chromecast:    boolValue(item.Chromecast),
		IsActive:      boolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		OwnerEmail:    ownerEmail,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(&item.UpdatedAt),
		EncrytionM3U8: boolValue(item.EncrytionM3u8),
		LogoUrl:       nullableTrimmedString(item.LogoURL),
	}
}
func toProtoPlan(item *model.Plan) *appv1.Plan {
	if item == nil {
		return nil
	}
	return &appv1.Plan{
		Id:            item.ID,
		Name:          item.Name,
		Description:   item.Description,
		Price:         item.Price,
		Cycle:         item.Cycle,
		StorageLimit:  item.StorageLimit,
		UploadLimit:   item.UploadLimit,
		DurationLimit: item.DurationLimit,
		QualityLimit:  item.QualityLimit,
		Features:      item.Features,
		IsActive:      boolValue(item.IsActive),
	}
}
func toProtoPayment(item *model.Payment) *appv1.Payment {
	if item == nil {
		return nil
	}
	return &appv1.Payment{
		Id:            item.ID,
		UserId:        item.UserID,
		PlanId:        item.PlanID,
		Amount:        item.Amount,
		Currency:      normalizeCurrency(item.Currency),
		Status:        normalizePaymentStatus(item.Status),
		Provider:      strings.ToUpper(stringValue(item.Provider)),
		TransactionId: item.TransactionID,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timestamppb.New(item.UpdatedAt.UTC()),
	}
}
func toProtoPlanSubscription(item *model.PlanSubscription) *appv1.PlanSubscription {
	if item == nil {
		return nil
	}
	return &appv1.PlanSubscription{
		Id:            item.ID,
		UserId:        item.UserID,
		PaymentId:     item.PaymentID,
		PlanId:        item.PlanID,
		TermMonths:    item.TermMonths,
		PaymentMethod: item.PaymentMethod,
		WalletAmount:  item.WalletAmount,
		TopupAmount:   item.TopupAmount,
		StartedAt:     timestamppb.New(item.StartedAt.UTC()),
		ExpiresAt:     timestamppb.New(item.ExpiresAt.UTC()),
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(item.UpdatedAt),
	}
}
func toProtoWalletTransaction(item *model.WalletTransaction) *appv1.WalletTransaction {
	if item == nil {
		return nil
	}
	return &appv1.WalletTransaction{
		Id:         item.ID,
		UserId:     item.UserID,
		Type:       item.Type,
		Amount:     item.Amount,
		Currency:   normalizeCurrency(item.Currency),
		Note:       item.Note,
		PaymentId:  item.PaymentID,
		PlanId:     item.PlanID,
		TermMonths: item.TermMonths,
		CreatedAt:  timeToProto(item.CreatedAt),
		UpdatedAt:  timeToProto(item.UpdatedAt),
	}
}
func timeToProto(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(value.UTC())
}
func boolValue(value *bool) bool {
	return value != nil && *value
}
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func int32PtrToInt64Ptr(value *int32) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}
func int64PtrToInt32Ptr(value *int64) *int32 {
	if value == nil {
		return nil
	}
	converted := int32(*value)
	return &converted
}
func int32Ptr(value int32) *int32 {
	return &value
}
func protoStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
func nullableTrimmedStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
func nullableTrimmedString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
func normalizeNotificationType(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(lower, "video"):
		return "video"
	case strings.Contains(lower, "payment"), strings.Contains(lower, "billing"):
		return "payment"
	case strings.Contains(lower, "warning"):
		return "warning"
	case strings.Contains(lower, "error"):
		return "error"
	case strings.Contains(lower, "success"):
		return "success"
	case strings.Contains(lower, "system"):
		return "system"
	default:
		return "info"
	}
}
func normalizeDomain(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, "/")
	return normalized
}
func normalizeAdFormat(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}
func adTemplateIsActive(value *bool) bool {
	return value == nil || *value
}
func playerConfigIsActive(value *bool) bool {
	return value == nil || *value
}
func unsetDefaultTemplates(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.AdTemplate{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}
func unsetDefaultPlayerConfigs(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.PlayerConfig{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}
func normalizePaymentStatus(status *string) string {
	value := strings.ToLower(strings.TrimSpace(stringValue(status)))
	switch value {
	case "success", "succeeded", "paid":
		return "success"
	case "failed", "error", "canceled", "cancelled":
		return "failed"
	case "pending", "processing":
		return "pending"
	default:
		if value == "" {
			return "success"
		}
		return value
	}
}
func normalizeCurrency(currency *string) string {
	value := strings.ToUpper(strings.TrimSpace(stringValue(currency)))
	if value == "" {
		return "USD"
	}
	return value
}
func normalizePaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case paymentMethodWallet:
		return paymentMethodWallet
	case paymentMethodTopup:
		return paymentMethodTopup
	default:
		return ""
	}
}
func normalizeOptionalPaymentMethod(value *string) *string {
	normalized := normalizePaymentMethod(stringValue(value))
	if normalized == "" {
		return nil
	}
	return &normalized
}
func buildInvoiceID(id string) string {
	trimmed := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	return "INV-" + strings.ToUpper(trimmed)
}
func buildTransactionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}
func buildInvoiceFilename(id string) string {
	return fmt.Sprintf("invoice-%s.txt", id)
}
func (s *appServices) buildPaymentInvoice(ctx context.Context, paymentRecord *model.Payment) (string, string, error) {
	details, err := s.loadPaymentInvoiceDetails(ctx, paymentRecord)
	if err != nil {
		return "", "", err
	}

	createdAt := formatOptionalTimestamp(paymentRecord.CreatedAt)
	lines := []string{
		"Stream API Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(paymentRecord.ID)),
		fmt.Sprintf("Payment ID: %s", paymentRecord.ID),
		fmt.Sprintf("User ID: %s", paymentRecord.UserID),
		fmt.Sprintf("Plan: %s", details.PlanName),
		fmt.Sprintf("Amount: %.2f %s", paymentRecord.Amount, normalizeCurrency(paymentRecord.Currency)),
		fmt.Sprintf("Status: %s", strings.ToUpper(normalizePaymentStatus(paymentRecord.Status))),
		fmt.Sprintf("Provider: %s", strings.ToUpper(stringValue(paymentRecord.Provider))),
		fmt.Sprintf("Payment Method: %s", strings.ToUpper(details.PaymentMethod)),
		fmt.Sprintf("Transaction ID: %s", stringValue(paymentRecord.TransactionID)),
	}

	if details.TermMonths != nil {
		lines = append(lines, fmt.Sprintf("Term: %d month(s)", *details.TermMonths))
	}
	if details.ExpiresAt != nil {
		lines = append(lines, fmt.Sprintf("Valid Until: %s", details.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	if details.WalletAmount > 0 {
		lines = append(lines, fmt.Sprintf("Wallet Applied: %.2f %s", details.WalletAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	if details.TopupAmount > 0 {
		lines = append(lines, fmt.Sprintf("Top-up Added: %.2f %s", details.TopupAmount, normalizeCurrency(paymentRecord.Currency)))
	}
	lines = append(lines, fmt.Sprintf("Created At: %s", createdAt))

	return strings.Join(lines, "\n"), buildInvoiceFilename(paymentRecord.ID), nil
}
func buildTopupInvoice(transaction *model.WalletTransaction) string {
	createdAt := formatOptionalTimestamp(transaction.CreatedAt)
	return strings.Join([]string{
		"Stream API Wallet Top-up Invoice",
		fmt.Sprintf("Invoice ID: %s", buildInvoiceID(transaction.ID)),
		fmt.Sprintf("Wallet Transaction ID: %s", transaction.ID),
		fmt.Sprintf("User ID: %s", transaction.UserID),
		fmt.Sprintf("Amount: %.2f %s", transaction.Amount, normalizeCurrency(transaction.Currency)),
		"Status: SUCCESS",
		fmt.Sprintf("Type: %s", strings.ToUpper(transaction.Type)),
		fmt.Sprintf("Note: %s", model.StringValue(transaction.Note)),
		fmt.Sprintf("Created At: %s", createdAt),
	}, "\n")
}
func (s *appServices) loadPaymentInvoiceDetails(ctx context.Context, paymentRecord *model.Payment) (*paymentInvoiceDetails, error) {
	details := &paymentInvoiceDetails{
		PlanName:      "Unknown plan",
		PaymentMethod: paymentMethodWallet,
	}

	if paymentRecord.PlanID != nil && strings.TrimSpace(*paymentRecord.PlanID) != "" {
		var planRecord model.Plan
		if err := s.db.WithContext(ctx).Where("id = ?", *paymentRecord.PlanID).First(&planRecord).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
		} else {
			details.PlanName = planRecord.Name
		}
	}

	var subscription model.PlanSubscription
	if err := s.db.WithContext(ctx).
		Where("payment_id = ?", paymentRecord.ID).
		Order("created_at DESC").
		First(&subscription).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return details, nil
	}

	details.TermMonths = &subscription.TermMonths
	details.PaymentMethod = normalizePaymentMethod(subscription.PaymentMethod)
	if details.PaymentMethod == "" {
		details.PaymentMethod = paymentMethodWallet
	}
	details.ExpiresAt = &subscription.ExpiresAt
	details.WalletAmount = subscription.WalletAmount
	details.TopupAmount = subscription.TopupAmount

	return details, nil
}
func buildSubscriptionNotification(userID, paymentID, invoiceID string, planRecord *model.Plan, subscription *model.PlanSubscription) *model.Notification {
	return &model.Notification{
		ID:      uuid.New().String(),
		UserID:  userID,
		Type:    "billing.subscription",
		Title:   "Subscription activated",
		Message: fmt.Sprintf("Your subscription to %s is active until %s.", planRecord.Name, subscription.ExpiresAt.UTC().Format("2006-01-02")),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
			"payment_id":      paymentID,
			"invoice_id":      invoiceID,
			"plan_id":         planRecord.ID,
			"term_months":     subscription.TermMonths,
			"payment_method":  subscription.PaymentMethod,
			"wallet_amount":   subscription.WalletAmount,
			"topup_amount":    subscription.TopupAmount,
			"plan_expires_at": subscription.ExpiresAt.UTC().Format(time.RFC3339),
		})),
	}
}

func buildReferralRewardNotification(userID string, rewardAmount float64, referee *model.User, paymentRecord *model.Payment) *model.Notification {
	refereeLabel := strings.TrimSpace(referee.Email)
	if username := strings.TrimSpace(stringValue(referee.Username)); username != "" {
		refereeLabel = "@" + username
	}
	return &model.Notification{
		ID:      uuid.New().String(),
		UserID:  userID,
		Type:    "billing.referral_reward",
		Title:   "Referral reward granted",
		Message: fmt.Sprintf("You received %.2f USD from %s's first subscription.", rewardAmount, refereeLabel),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
			"payment_id": paymentRecord.ID,
			"referee_id": referee.ID,
			"amount":     rewardAmount,
		})),
	}
}

func (s *appServices) maybeGrantReferralReward(ctx context.Context, tx *gorm.DB, input paymentExecutionInput, paymentRecord *model.Payment, subscription *model.PlanSubscription) (*referralRewardResult, error) {
	if paymentRecord == nil || subscription == nil || input.Plan == nil {
		return &referralRewardResult{}, nil
	}
	if subscription.PaymentMethod != paymentMethodWallet && subscription.PaymentMethod != paymentMethodTopup {
		return &referralRewardResult{}, nil
	}

	referee, err := lockUserForUpdate(ctx, tx, input.UserID)
	if err != nil {
		return nil, err
	}
	if referee.ReferredByUserID == nil || strings.TrimSpace(*referee.ReferredByUserID) == "" {
		return &referralRewardResult{}, nil
	}
	if referralRewardProcessed(referee) {
		return &referralRewardResult{}, nil
	}

	var subscriptionCount int64
	if err := tx.WithContext(ctx).
		Model(&model.PlanSubscription{}).
		Where("user_id = ?", referee.ID).
		Count(&subscriptionCount).Error; err != nil {
		return nil, err
	}
	if subscriptionCount != 1 {
		return &referralRewardResult{}, nil
	}

	referrer, err := lockUserForUpdate(ctx, tx, strings.TrimSpace(*referee.ReferredByUserID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &referralRewardResult{}, nil
		}
		return nil, err
	}
	if referrer.ID == referee.ID || !referralUserEligible(referrer) {
		return &referralRewardResult{}, nil
	}

	bps := effectiveReferralRewardBps(referrer.ReferralRewardBps)
	if bps <= 0 {
		return &referralRewardResult{}, nil
	}
	baseAmount := input.Plan.Price * float64(input.TermMonths)
	if baseAmount <= 0 {
		return &referralRewardResult{}, nil
	}
	rewardAmount := baseAmount * float64(bps) / 10000
	if rewardAmount <= 0 {
		return &referralRewardResult{}, nil
	}

	currency := normalizeCurrency(paymentRecord.Currency)
	rewardTransaction := &model.WalletTransaction{
		ID:        uuid.New().String(),
		UserID:    referrer.ID,
		Type:      walletTransactionTypeReferralReward,
		Amount:    rewardAmount,
		Currency:  model.StringPtr(currency),
		Note:      model.StringPtr(fmt.Sprintf("Referral reward for %s first subscription", referee.Email)),
		PaymentID: &paymentRecord.ID,
		PlanID:    &input.Plan.ID,
	}
	if err := tx.Create(rewardTransaction).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(buildReferralRewardNotification(referrer.ID, rewardAmount, referee, paymentRecord)).Error; err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	updates := map[string]any{
		"referral_reward_granted_at": now,
		"referral_reward_payment_id": paymentRecord.ID,
		"referral_reward_amount":     rewardAmount,
	}
	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", referee.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	referee.ReferralRewardGrantedAt = &now
	referee.ReferralRewardPaymentID = &paymentRecord.ID
	referee.ReferralRewardAmount = &rewardAmount
	return &referralRewardResult{Granted: true, Amount: rewardAmount}, nil
}
func isAllowedTermMonths(value int32) bool {
	_, ok := allowedTermMonths[value]
	return ok
}
func lockUserForUpdate(ctx context.Context, tx *gorm.DB, userID string) (*model.User, error) {
	if tx.Dialector.Name() == "sqlite" {
		res := tx.WithContext(ctx).Exec("UPDATE user SET id = id WHERE id = ?", userID)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, gorm.ErrRecordNotFound
		}
	}

	var user model.User
	if err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", userID).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
func maxFloat(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}
func formatOptionalTimestamp(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
func mustMarshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
