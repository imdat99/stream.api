package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

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
