package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	authapi "stream.api/internal/api/auth"
	paymentapi "stream.api/internal/api/payment"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/middleware"
	"stream.api/internal/video/runtime/domain"
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
func buildAdminJob(job *domain.Job) *appv1.AdminJob {
	if job == nil {
		return nil
	}
	return &appv1.AdminJob{
		Id:            job.ID,
		Status:        string(job.Status),
		Priority:      int32(job.Priority),
		UserId:        job.UserID,
		Name:          job.Name,
		TimeLimit:     job.TimeLimit,
		InputUrl:      job.InputURL,
		OutputUrl:     job.OutputURL,
		TotalDuration: job.TotalDuration,
		CurrentTime:   job.CurrentTime,
		Progress:      job.Progress,
		AgentId:       job.AgentID,
		Logs:          job.Logs,
		Config:        job.Config,
		Cancelled:     job.Cancelled,
		RetryCount:    int32(job.RetryCount),
		MaxRetries:    int32(job.MaxRetries),
		CreatedAt:     timestamppb.New(job.CreatedAt),
		UpdatedAt:     timestamppb.New(job.UpdatedAt),
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
func (s *appServices) saveAdminVideoAdConfig(ctx context.Context, tx *gorm.DB, videoID, userID string, adTemplateID *string) error {
	if adTemplateID == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*adTemplateID)
	if trimmed == "" {
		return tx.Where("video_id = ? AND user_id = ?", videoID, userID).Delete(&model.VideoAdConfig{}).Error
	}

	var template model.AdTemplate
	if err := tx.WithContext(ctx).Where("id = ? AND user_id = ?", trimmed, userID).First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("Ad template not found")
		}
		return err
	}

	var existing model.VideoAdConfig
	if err := tx.WithContext(ctx).Where("video_id = ? AND user_id = ?", videoID, userID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&model.VideoAdConfig{
				VideoID:      videoID,
				UserID:       userID,
				AdTemplateID: template.ID,
				VastTagURL:   template.VastTagURL,
				AdFormat:     template.AdFormat,
				Duration:     template.Duration,
			}).Error
		}
		return err
	}

	existing.AdTemplateID = template.ID
	existing.VastTagURL = template.VastTagURL
	existing.AdFormat = template.AdFormat
	existing.Duration = template.Duration
	return tx.Save(&existing).Error
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

	var videoCount int64
	if err := s.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", user.ID).Count(&videoCount).Error; err != nil {
		return nil, err
	}
	payload.VideoCount = videoCount

	walletBalance, err := model.GetWalletBalance(ctx, s.db, user.ID)
	if err != nil {
		return nil, err
	}
	payload.WalletBalance = walletBalance

	if user.PlanID != nil && strings.TrimSpace(*user.PlanID) != "" {
		var plan model.Plan
		if err := s.db.WithContext(ctx).Select("id, name").Where("id = ?", *user.PlanID).First(&plan).Error; err == nil {
			payload.PlanName = nullableTrimmedString(&plan.Name)
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	return payload, nil
}
func (s *appServices) buildAdminVideo(ctx context.Context, video *model.Video) (*appv1.AdminVideo, error) {
	if video == nil {
		return nil, nil
	}

	statusValue := stringValue(video.Status)
	if statusValue == "" {
		statusValue = "ready"
	}

	payload := &appv1.AdminVideo{
		Id:          video.ID,
		UserId:      video.UserID,
		Title:       video.Title,
		Description: nullableTrimmedString(video.Description),
		Url:         video.URL,
		Status:      strings.ToLower(statusValue),
		Size:        video.Size,
		Duration:    video.Duration,
		Format:      video.Format,
		CreatedAt:   timeToProto(video.CreatedAt),
		UpdatedAt:   timestamppb.New(video.UpdatedAt.UTC()),
	}

	var user model.User
	if err := s.db.WithContext(ctx).Select("id, email").Where("id = ?", video.UserID).First(&user).Error; err == nil {
		payload.OwnerEmail = nullableTrimmedString(&user.Email)
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	var adConfig model.VideoAdConfig
	if err := s.db.WithContext(ctx).Where("video_id = ?", video.ID).First(&adConfig).Error; err == nil {
		payload.AdTemplateId = nullableTrimmedString(&adConfig.AdTemplateID)
		var template model.AdTemplate
		if err := s.db.WithContext(ctx).Select("id, name").Where("id = ?", adConfig.AdTemplateID).First(&template).Error; err == nil {
			payload.AdTemplateName = nullableTrimmedString(&template.Name)
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return payload, nil
}
func (s *appServices) buildAdminPayment(ctx context.Context, payment *model.Payment) (*appv1.AdminPayment, error) {
	if payment == nil {
		return nil, nil
	}

	currency := normalizeCurrency(payment.Currency)
	if strings.TrimSpace(currency) == "" {
		currency = "USD"
	}

	payload := &appv1.AdminPayment{
		Id:            payment.ID,
		UserId:        payment.UserID,
		PlanId:        nullableTrimmedString(payment.PlanID),
		Amount:        payment.Amount,
		Currency:      currency,
		Status:        normalizePaymentStatus(payment.Status),
		Provider:      strings.ToUpper(stringValue(payment.Provider)),
		TransactionId: nullableTrimmedString(payment.TransactionID),
		InvoiceId:     payment.ID,
		CreatedAt:     timeToProto(payment.CreatedAt),
		UpdatedAt:     timestamppb.New(payment.UpdatedAt.UTC()),
	}

	var user model.User
	if err := s.db.WithContext(ctx).Select("id, email").Where("id = ?", payment.UserID).First(&user).Error; err == nil {
		payload.UserEmail = nullableTrimmedString(&user.Email)
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if payment.PlanID != nil && strings.TrimSpace(*payment.PlanID) != "" {
		var plan model.Plan
		if err := s.db.WithContext(ctx).Select("id, name").Where("id = ?", *payment.PlanID).First(&plan).Error; err == nil {
			payload.PlanName = nullableTrimmedString(&plan.Name)
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	var subscription model.PlanSubscription
	if err := s.db.WithContext(ctx).Where("payment_id = ?", payment.ID).Order("created_at DESC").First(&subscription).Error; err == nil {
		payload.TermMonths = &subscription.TermMonths
		payload.PaymentMethod = nullableTrimmedString(&subscription.PaymentMethod)
		expiresAt := subscription.ExpiresAt.UTC().Format(time.RFC3339)
		payload.ExpiresAt = nullableTrimmedString(&expiresAt)
		payload.WalletAmount = &subscription.WalletAmount
		payload.TopupAmount = &subscription.TopupAmount
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return payload, nil
}
func (s *appServices) loadPlanUsageCounts(ctx context.Context, planID string) (int64, int64, int64, error) {
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
func normalizeAdminAdFormatValue(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}
func validateAdminAdTemplateInput(userID, name, vastTagURL, adFormat string, duration *int64) string {
	if strings.TrimSpace(userID) == "" {
		return "User ID is required"
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(vastTagURL) == "" {
		return "Name and VAST URL are required"
	}
	format := normalizeAdminAdFormatValue(adFormat)
	if format == "mid-roll" && (duration == nil || *duration <= 0) {
		return "Duration is required for mid-roll templates"
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
func (s *appServices) buildAdminPlan(ctx context.Context, plan *model.Plan) (*appv1.AdminPlan, error) {
	if plan == nil {
		return nil, nil
	}

	userCount, paymentCount, subscriptionCount, err := s.loadPlanUsageCounts(ctx, plan.ID)
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

	var user model.User
	if err := s.db.WithContext(ctx).Select("id, email").Where("id = ?", item.UserID).First(&user).Error; err == nil {
		payload.OwnerEmail = nullableTrimmedString(&user.Email)
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return payload, nil
}
func (s *appServices) authenticate(ctx context.Context) (*middleware.AuthResult, error) {
	return s.authenticator.Authenticate(ctx)
}
func statusErrorWithBody(ctx context.Context, grpcCode codes.Code, httpCode int, message string, data interface{}) error {
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
func cookieValueFromHeader(cookieHeader string, name string) string {
	cookieHeader = strings.TrimSpace(cookieHeader)
	if cookieHeader == "" {
		return ""
	}
	request := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
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
func clearCookieHeader(name string) string {
	return (&http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true}).String()
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
func toProtoVideo(item *model.Video) *appv1.Video {
	if item == nil {
		return nil
	}
	statusValue := stringValue(item.Status)
	if statusValue == "" {
		statusValue = "ready"
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
	}
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
func toProtoUserPayload(user *authapi.UserPayload) *appv1.User {
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
func toProtoUser(user *authapi.UserPayload) *appv1.User {
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
func toProtoPreferences(pref *model.UserPreference) *appv1.Preferences {
	if pref == nil {
		return nil
	}
	return &appv1.Preferences{
		EmailNotifications:     boolValue(pref.EmailNotifications),
		PushNotifications:      boolValue(pref.PushNotifications),
		MarketingNotifications: pref.MarketingNotifications,
		TelegramNotifications:  pref.TelegramNotifications,
		Autoplay:               pref.Autoplay,
		Loop:                   pref.Loop,
		Muted:                  pref.Muted,
		ShowControls:           boolValue(pref.ShowControls),
		Pip:                    boolValue(pref.Pip),
		Airplay:                boolValue(pref.Airplay),
		Chromecast:             boolValue(pref.Chromecast),
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
func toProtoPaymentHistoryItem(item *paymentapi.PaymentHistoryItem) *appv1.PaymentHistoryItem {
	if item == nil {
		return nil
	}
	return &appv1.PaymentHistoryItem{
		Id:            item.ID,
		Amount:        item.Amount,
		Currency:      item.Currency,
		Status:        item.Status,
		PlanId:        item.PlanID,
		PlanName:      item.PlanName,
		InvoiceId:     item.InvoiceID,
		Kind:          item.Kind,
		TermMonths:    item.TermMonths,
		PaymentMethod: item.PaymentMethod,
		ExpiresAt:     timeToProto(item.ExpiresAt),
		CreatedAt:     timeToProto(item.CreatedAt),
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
func nullableInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
func nullableInt64Ptr(value int64) *int64 {
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
func unsetDefaultTemplates(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.AdTemplate{}).Where("user_id = ?", userID)
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
		Metadata: model.StringPtr(mustMarshalJSON(map[string]interface{}{
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
func isAllowedTermMonths(value int32) bool {
	_, ok := allowedTermMonths[value]
	return ok
}
func lockUserForUpdate(ctx context.Context, tx *gorm.DB, userID string) (*model.User, error) {
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
func mustMarshalJSON(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
