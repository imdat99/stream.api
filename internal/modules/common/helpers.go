package common

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
	videodomain "stream.api/internal/video/runtime/domain"
	runtimeservices "stream.api/internal/video/runtime/services"
)

type APIErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func AdminPageLimitOffset(pageValue int32, limitValue int32) (int32, int32, int) {
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

func BuildAdminJob(job *videodomain.Job) *appv1.AdminJob {
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
		VideoId:       StringPointerOrNil(job.VideoID),
	}
}

func BuildAdminAgent(agent *runtimeservices.AgentWithStats) *appv1.AdminAgent {
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

func NormalizeAdminRoleValue(value string) string {
	role := strings.ToUpper(strings.TrimSpace(value))
	if role == "" {
		return "USER"
	}
	return role
}

func IsValidAdminRoleValue(role string) bool {
	switch NormalizeAdminRoleValue(role) {
	case "USER", "ADMIN", "BLOCK":
		return true
	default:
		return false
	}
}

func ReferralUserEligible(user *model.User) bool {
	if user == nil || user.ReferralEligible == nil {
		return true
	}
	return *user.ReferralEligible
}

func EffectiveReferralRewardBps(value *int32) int32 {
	if value == nil {
		return DefaultReferralRewardBps
	}
	if *value < 0 {
		return 0
	}
	if *value > 10000 {
		return 10000
	}
	return *value
}

func ReferralRewardBpsToPercent(value int32) float64 {
	return float64(value) / 100
}

func ReferralRewardProcessed(user *model.User) bool {
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

func BoolValue(value *bool) bool {
	return value != nil && *value
}

func StringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func NullableTrimmedStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func NullableTrimmedString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func Int32PtrToInt64Ptr(value *int32) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func Int64PtrToInt32Ptr(value *int64) *int32 {
	if value == nil {
		return nil
	}
	converted := int32(*value)
	return &converted
}

func Int32Ptr(value int32) *int32 {
	return &value
}

func ProtoStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func SafeRole(role *string) string {
	if role == nil || strings.TrimSpace(*role) == "" {
		return "USER"
	}
	return *role
}

func StringPointerOrNil(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func TimeToProto(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func MaxFloat(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}

func FormatOptionalTimestamp(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func MustMarshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func NormalizeNotificationType(value string) string {
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

func NormalizeDomain(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, "/")
	return normalized
}

func NormalizeAdFormat(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}

func AdTemplateIsActive(value *bool) bool {
	return value == nil || *value
}

func PlayerConfigIsActive(value *bool) bool {
	return value == nil || *value
}

func UnsetDefaultTemplates(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.AdTemplate{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}

func UnsetDefaultPlayerConfigs(tx *gorm.DB, userID, excludeID string) error {
	query := tx.Model(&model.PlayerConfig{}).Where("user_id = ?", userID)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	return query.Update("is_default", false).Error
}

func NormalizePaymentStatus(statusValue *string) string {
	value := strings.ToLower(strings.TrimSpace(StringValue(statusValue)))
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

func NormalizeCurrency(currency *string) string {
	value := strings.ToUpper(strings.TrimSpace(StringValue(currency)))
	if value == "" {
		return "USD"
	}
	return value
}

func NormalizePaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case PaymentMethodWallet:
		return PaymentMethodWallet
	case PaymentMethodTopup:
		return PaymentMethodTopup
	default:
		return ""
	}
}

func NormalizeOptionalPaymentMethod(value *string) *string {
	normalized := NormalizePaymentMethod(StringValue(value))
	if normalized == "" {
		return nil
	}
	return &normalized
}

func BuildInvoiceID(id string) string {
	trimmed := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	return "INV-" + strings.ToUpper(trimmed)
}

func BuildTransactionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func BuildInvoiceFilename(id string) string {
	return fmt.Sprintf("invoice-%s.txt", id)
}

func BuildTopupInvoice(transaction *model.WalletTransaction) string {
	createdAt := FormatOptionalTimestamp(transaction.CreatedAt)
	return strings.Join([]string{
		"Stream API Wallet Top-up Invoice",
		fmt.Sprintf("Invoice ID: %s", BuildInvoiceID(transaction.ID)),
		fmt.Sprintf("Wallet Transaction ID: %s", transaction.ID),
		fmt.Sprintf("User ID: %s", transaction.UserID),
		fmt.Sprintf("Amount: %.2f %s", transaction.Amount, NormalizeCurrency(transaction.Currency)),
		"Status: SUCCESS",
		fmt.Sprintf("Type: %s", strings.ToUpper(transaction.Type)),
		fmt.Sprintf("Note: %s", model.StringValue(transaction.Note)),
		fmt.Sprintf("Created At: %s", createdAt),
	}, "\n")
}

func StatusErrorWithBody(ctx context.Context, grpcCode codes.Code, httpCode int, message string, data any) error {
	body := APIErrorBody{Code: httpCode, Message: message, Data: data}
	encoded, err := json.Marshal(body)
	if err == nil {
		_ = grpc.SetTrailer(ctx, metadata.Pairs("x-error-body", string(encoded)))
	}
	return status.Error(grpcCode, message)
}

func IsAllowedTermMonths(value int32) bool {
	_, ok := AllowedTermMonths[value]
	return ok
}

func LockUserForUpdate(ctx context.Context, tx *gorm.DB, userID string) (*model.User, error) {
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

func MessageResponse(message string) *appv1.MessageResponse {
	return &appv1.MessageResponse{Message: message}
}

func EnsurePaidPlan(user *model.User) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	if user.PlanID == nil || strings.TrimSpace(*user.PlanID) == "" {
		return status.Error(codes.PermissionDenied, AdTemplateUpgradeRequiredMessage)
	}
	return nil
}

func PlayerConfigActionAllowed(user *model.User, configCount int64, action string) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	if user.PlanID != nil && strings.TrimSpace(*user.PlanID) != "" {
		return nil
	}

	switch action {
	case "create":
		if configCount > 0 {
			return status.Error(codes.FailedPrecondition, PlayerConfigFreePlanLimitMessage)
		}
	case "update", "set-default", "toggle-active":
		if configCount > 1 {
			return status.Error(codes.FailedPrecondition, PlayerConfigFreePlanReconciliationMessage)
		}
	}
	return nil
}

func GenerateOAuthState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func GoogleOAuthStateCacheKey(state string) string {
	return "google_oauth_state:" + state
}

func ToProtoVideo(item *model.Video, jobID ...string) *appv1.Video {
	if item == nil {
		return nil
	}
	statusValue := StringValue(item.Status)
	if statusValue == "" {
		statusValue = "ready"
	}
	var linkedJobID *string
	if len(jobID) > 0 {
		linkedJobID = StringPointerOrNil(jobID[0])
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
		CreatedAt:        TimeToProto(item.CreatedAt),
		UpdatedAt:        timestamppb.New(item.UpdatedAt.UTC()),
		JobId:            linkedJobID,
	}
}

func NormalizeVideoStatusValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "processing", "pending":
		return "processing"
	case "failed", "error":
		return "failed"
	default:
		return "ready"
	}
}

func DetectStorageType(rawURL string) string {
	if ShouldDeleteStoredObject(rawURL) {
		return "S3"
	}
	return "WORKER"
}

func ShouldDeleteStoredObject(rawURL string) bool {
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

func ExtractObjectKey(rawURL string) string {
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

func ToProtoUser(user *UserPayload) *appv1.User {
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
		PlanStartedAt:     TimeToProto(user.PlanStartedAt),
		PlanExpiresAt:     TimeToProto(user.PlanExpiresAt),
		PlanTermMonths:    user.PlanTermMonths,
		PlanPaymentMethod: user.PlanPaymentMethod,
		PlanExpiringSoon:  user.PlanExpiringSoon,
		WalletBalance:     user.WalletBalance,
		Language:          user.Language,
		Locale:            user.Locale,
		CreatedAt:         TimeToProto(user.CreatedAt),
		UpdatedAt:         timestamppb.New(user.UpdatedAt),
	}
}

func ToProtoPreferences(pref *model.UserPreference) *appv1.Preferences {
	if pref == nil {
		return nil
	}
	return &appv1.Preferences{
		EmailNotifications:     BoolValue(pref.EmailNotifications),
		PushNotifications:      BoolValue(pref.PushNotifications),
		MarketingNotifications: pref.MarketingNotifications,
		TelegramNotifications:  pref.TelegramNotifications,
		Language:               model.StringValue(pref.Language),
		Locale:                 model.StringValue(pref.Locale),
	}
}

func ToProtoNotification(item model.Notification) *appv1.Notification {
	return &appv1.Notification{
		Id:          item.ID,
		Type:        NormalizeNotificationType(item.Type),
		Title:       item.Title,
		Message:     item.Message,
		Read:        item.IsRead,
		ActionUrl:   item.ActionURL,
		ActionLabel: item.ActionLabel,
		CreatedAt:   TimeToProto(item.CreatedAt),
	}
}

func ToProtoDomain(item *model.Domain) *appv1.Domain {
	if item == nil {
		return nil
	}
	return &appv1.Domain{
		Id:        item.ID,
		Name:      item.Name,
		CreatedAt: TimeToProto(item.CreatedAt),
		UpdatedAt: TimeToProto(item.UpdatedAt),
	}
}

func ToProtoAdTemplate(item *model.AdTemplate) *appv1.AdTemplate {
	if item == nil {
		return nil
	}
	return &appv1.AdTemplate{
		Id:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		VastTagUrl:  item.VastTagURL,
		AdFormat:    model.StringValue(item.AdFormat),
		Duration:    Int64PtrToInt32Ptr(item.Duration),
		IsActive:    BoolValue(item.IsActive),
		IsDefault:   item.IsDefault,
		CreatedAt:   TimeToProto(item.CreatedAt),
		UpdatedAt:   TimeToProto(item.UpdatedAt),
	}
}

func ToProtoPlayerConfig(item *model.PlayerConfig) *appv1.PlayerConfig {
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
		ShowControls:  BoolValue(item.ShowControls),
		Pip:           BoolValue(item.Pip),
		Airplay:       BoolValue(item.Airplay),
		Chromecast:    BoolValue(item.Chromecast),
		IsActive:      BoolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		CreatedAt:     TimeToProto(item.CreatedAt),
		UpdatedAt:     TimeToProto(&item.UpdatedAt),
		EncrytionM3U8: BoolValue(item.EncrytionM3u8),
		LogoUrl:       NullableTrimmedString(item.LogoURL),
	}
}

func ToProtoAdminPlayerConfig(item *model.PlayerConfig, ownerEmail *string) *appv1.AdminPlayerConfig {
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
		ShowControls:  BoolValue(item.ShowControls),
		Pip:           BoolValue(item.Pip),
		Airplay:       BoolValue(item.Airplay),
		Chromecast:    BoolValue(item.Chromecast),
		IsActive:      BoolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		OwnerEmail:    ownerEmail,
		CreatedAt:     TimeToProto(item.CreatedAt),
		UpdatedAt:     TimeToProto(&item.UpdatedAt),
		EncrytionM3U8: BoolValue(item.EncrytionM3u8),
		LogoUrl:       NullableTrimmedString(item.LogoURL),
	}
}

func ToProtoPlan(item *model.Plan) *appv1.Plan {
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
		IsActive:      BoolValue(item.IsActive),
	}
}

func ToProtoPayment(item *model.Payment) *appv1.Payment {
	if item == nil {
		return nil
	}
	return &appv1.Payment{
		Id:            item.ID,
		UserId:        item.UserID,
		PlanId:        item.PlanID,
		Amount:        item.Amount,
		Currency:      NormalizeCurrency(item.Currency),
		Status:        NormalizePaymentStatus(item.Status),
		Provider:      strings.ToUpper(StringValue(item.Provider)),
		TransactionId: item.TransactionID,
		CreatedAt:     TimeToProto(item.CreatedAt),
		UpdatedAt:     timestamppb.New(item.UpdatedAt.UTC()),
	}
}

func ToProtoPlanSubscription(item *model.PlanSubscription) *appv1.PlanSubscription {
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
		CreatedAt:     TimeToProto(item.CreatedAt),
		UpdatedAt:     TimeToProto(item.UpdatedAt),
	}
}

func ToProtoWalletTransaction(item *model.WalletTransaction) *appv1.WalletTransaction {
	if item == nil {
		return nil
	}
	return &appv1.WalletTransaction{
		Id:         item.ID,
		UserId:     item.UserID,
		Type:       item.Type,
		Amount:     item.Amount,
		Currency:   NormalizeCurrency(item.Currency),
		Note:       item.Note,
		PaymentId:  item.PaymentID,
		PlanId:     item.PlanID,
		TermMonths: item.TermMonths,
		CreatedAt:  TimeToProto(item.CreatedAt),
		UpdatedAt:  TimeToProto(item.UpdatedAt),
	}
}
