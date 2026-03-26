package users

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/internal/modules/common"
)

var (
	ErrEmailRequired          = errors.New("Email is required")
	ErrEmailAlreadyRegistered = errors.New("Email already registered")
)

type Module struct {
	runtime *common.Runtime
}

type updateProfileInput struct {
	Username *string
	Email    *string
	Language *string
	Locale   *string
}

type updatePreferencesInput struct {
	EmailNotifications     *bool
	PushNotifications      *bool
	MarketingNotifications *bool
	TelegramNotifications  *bool
	Language               *string
	Locale                 *string
}

type usagePayload struct {
	UserID       string `json:"user_id"`
	TotalVideos  int64  `json:"total_videos"`
	TotalStorage int64  `json:"total_storage"`
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) GetMe(ctx context.Context, userID string) (*UserView, error) {
	result, err := m.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := common.BuildUserPayload(ctx, m.runtime.DB(), result.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return mapUserPayload(payload), nil
}

func (m *Module) GetUserByID(ctx context.Context, req *wrapperspb.StringValue) (*UserView, error) {
	_, err := m.runtime.Authenticator().RequireTrustedMetadata(ctx)
	if err != nil {
		return nil, err
	}
	u := query.User
	user, err := u.WithContext(ctx).Where(u.ID.Eq(req.Value)).First()
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Unauthorized")
	}
	payload, err := common.BuildUserPayload(ctx, m.runtime.DB(), user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return mapUserPayload(payload), nil
}

func (m *Module) UpdateMe(ctx context.Context, cmd UpdateProfileCommand) (*UserView, error) {
	updatedUser, err := m.updateUserProfile(ctx, cmd.UserID, updateProfileInput{Username: cmd.Username, Email: cmd.Email, Language: cmd.Language, Locale: cmd.Locale})
	if err != nil {
		switch {
		case errors.Is(err, ErrEmailRequired), errors.Is(err, ErrEmailAlreadyRegistered):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Error(codes.Internal, "Failed to update profile")
		}
	}
	payload, err := common.BuildUserPayload(ctx, m.runtime.DB(), updatedUser)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return mapUserPayload(payload), nil
}

func (m *Module) DeleteMe(ctx context.Context, userID string) error {
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.WalletTransaction{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.PlanSubscription{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.UserPreference{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.Payment{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil { return err }
		if err := tx.Where("id = ?", userID).Delete(&model.User{}).Error; err != nil { return err }
		return nil
	}); err != nil {
		m.runtime.Logger().Error("Failed to delete user", "error", err)
		return status.Error(codes.Internal, "Failed to delete account")
	}
	return nil
}

func (m *Module) ClearMyData(ctx context.Context, userID string) error {
	if err := m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil { return err }
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{"storage_used": 0}).Error; err != nil { return err }
		return nil
	}); err != nil {
		m.runtime.Logger().Error("Failed to clear user data", "error", err)
		return status.Error(codes.Internal, "Failed to clear data")
	}
	return nil
}

func (m *Module) GetPreferences(ctx context.Context, userID string) (*PreferencesView, error) {
	pref, err := m.loadUserPreferences(ctx, userID)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to load preferences") }
	return mapPreferences(pref), nil
}

func (m *Module) UpdatePreferences(ctx context.Context, cmd UpdatePreferencesCommand) (*PreferencesView, error) {
	pref, err := m.updateUserPreferences(ctx, cmd.UserID, updatePreferencesInput{EmailNotifications: cmd.EmailNotifications, PushNotifications: cmd.PushNotifications, MarketingNotifications: cmd.MarketingNotifications, TelegramNotifications: cmd.TelegramNotifications, Language: cmd.Language, Locale: cmd.Locale})
	if err != nil { return nil, status.Error(codes.Internal, "Failed to save preferences") }
	return mapPreferences(pref), nil
}

func (m *Module) GetUsage(ctx context.Context, user *model.User) (*UsageView, error) {
	payload, err := m.loadUsage(ctx, user)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to load usage") }
	return &UsageView{UserID: payload.UserID, TotalVideos: payload.TotalVideos, TotalStorage: payload.TotalStorage}, nil
}

func (m *Module) ListNotifications(ctx context.Context, userID string) (*ListNotificationsResult, error) {
	var rows []model.Notification
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&rows).Error; err != nil { m.runtime.Logger().Error("Failed to list notifications", "error", err); return nil, status.Error(codes.Internal, "Failed to load notifications") }
	items := make([]NotificationView, 0, len(rows))
	for _, row := range rows { items = append(items, NotificationView{Notification: row}) }
	return &ListNotificationsResult{Items: items}, nil
}

func (m *Module) MarkNotificationRead(ctx context.Context, cmd MarkNotificationCommand) error {
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return status.Error(codes.NotFound, "Notification not found") }
	res := m.runtime.DB().WithContext(ctx).Model(&model.Notification{}).Where("id = ? AND user_id = ?", id, cmd.UserID).Update("is_read", true)
	if res.Error != nil { m.runtime.Logger().Error("Failed to update notification", "error", res.Error); return status.Error(codes.Internal, "Failed to update notification") }
	if res.RowsAffected == 0 { return status.Error(codes.NotFound, "Notification not found") }
	return nil
}

func (m *Module) MarkAllNotificationsRead(ctx context.Context, userID string) error {
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Notification{}).Where("user_id = ? AND is_read = ?", userID, false).Update("is_read", true).Error; err != nil { m.runtime.Logger().Error("Failed to mark all notifications as read", "error", err); return status.Error(codes.Internal, "Failed to update notifications") }
	return nil
}

func (m *Module) DeleteNotification(ctx context.Context, cmd MarkNotificationCommand) error {
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return status.Error(codes.NotFound, "Notification not found") }
	res := m.runtime.DB().WithContext(ctx).Where("id = ? AND user_id = ?", id, cmd.UserID).Delete(&model.Notification{})
	if res.Error != nil { m.runtime.Logger().Error("Failed to delete notification", "error", res.Error); return status.Error(codes.Internal, "Failed to delete notification") }
	if res.RowsAffected == 0 { return status.Error(codes.NotFound, "Notification not found") }
	return nil
}

func (m *Module) ClearNotifications(ctx context.Context, userID string) error {
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil { m.runtime.Logger().Error("Failed to clear notifications", "error", err); return status.Error(codes.Internal, "Failed to clear notifications") }
	return nil
}

func (m *Module) ResolveSignupReferrerID(ctx context.Context, refUsername string, newUsername string) (*string, error) {
	trimmedRefUsername := strings.TrimSpace(refUsername)
	if trimmedRefUsername == "" || strings.EqualFold(trimmedRefUsername, strings.TrimSpace(newUsername)) { return nil, nil }
	referrer, err := m.resolveReferralUserByUsername(ctx, trimmedRefUsername)
	if err != nil { return nil, err }
	if referrer == nil { return nil, nil }
	return &referrer.ID, nil
}

func (m *Module) LoadReferralUserByUsernameStrict(ctx context.Context, username string) (*model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" { return nil, status.Error(codes.InvalidArgument, "Referral username is required") }
	users, err := m.loadReferralUsersByUsername(ctx, trimmed)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to resolve referral user") }
	if len(users) == 0 { return nil, status.Error(codes.InvalidArgument, "Referral user not found") }
	if len(users) > 1 { return nil, status.Error(codes.InvalidArgument, "Referral username is ambiguous") }
	return &users[0], nil
}

func (m *Module) EnsurePlanExists(ctx context.Context, planID *string) error {
	if planID == nil { return nil }
	trimmed := strings.TrimSpace(*planID)
	if trimmed == "" { return nil }
	var count int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Plan{}).Where("id = ?", trimmed).Count(&count).Error; err != nil { return status.Error(codes.Internal, "Failed to validate plan") }
	if count == 0 { return status.Error(codes.InvalidArgument, "Plan not found") }
	return nil
}

func (m *Module) ListAdminUsers(ctx context.Context, queryValue ListAdminUsersQuery) (*ListAdminUsersResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil { return nil, err }
	page, limit, offset := common.AdminPageLimitOffset(queryValue.Page, queryValue.Limit)
	limitInt := int(limit)
	db := m.runtime.DB().WithContext(ctx).Model(&model.User{})
	if search := strings.TrimSpace(queryValue.Search); search != "" { like := "%" + search + "%"; db = db.Where("email ILIKE ? OR username ILIKE ?", like, like) }
	if role := strings.TrimSpace(queryValue.Role); role != "" { db = db.Where("UPPER(role) = ?", strings.ToUpper(role)) }
	var total int64
	if err := db.Count(&total).Error; err != nil { return nil, status.Error(codes.Internal, "Failed to list users") }
	var users []model.User
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&users).Error; err != nil { return nil, status.Error(codes.Internal, "Failed to list users") }
	items := make([]AdminUserView, 0, len(users))
	for _, user := range users {
		payload, err := m.buildAdminUser(ctx, &user)
		if err != nil { return nil, status.Error(codes.Internal, "Failed to list users") }
		items = append(items, payload)
	}
	return &ListAdminUsersResult{Items: items, Total: total, Page: page, Limit: limit}, nil
}

func (m *Module) GetAdminUser(ctx context.Context, queryValue GetAdminUserQuery) (*AdminUserDetailView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil { return nil, err }
	id := strings.TrimSpace(queryValue.ID)
	if id == "" { return nil, status.Error(codes.NotFound, "User not found") }
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.NotFound, "User not found") }; return nil, status.Error(codes.Internal, "Failed to get user") }
	var subscription *model.PlanSubscription
	var subscriptionRecord model.PlanSubscription
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").First(&subscriptionRecord).Error; err == nil { subscription = &subscriptionRecord } else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.Internal, "Failed to get user") }
	detail, err := m.buildAdminUserDetail(ctx, &user, subscription)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to get user") }
	return &detail, nil
}

func (m *Module) CreateAdminUser(ctx context.Context, cmd CreateAdminUserCommand) (*AdminUserView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil { return nil, err }
	email := strings.TrimSpace(cmd.Email)
	password := cmd.Password
	if email == "" || password == "" { return nil, status.Error(codes.InvalidArgument, "Email and password are required") }
	role := common.NormalizeAdminRoleValue(cmd.Role)
	if !common.IsValidAdminRoleValue(role) { return nil, status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK") }
	if err := m.EnsurePlanExists(ctx, cmd.PlanID); err != nil { return nil, err }
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to hash password") }
	user := &model.User{ID: uuid.New().String(), Email: email, Password: model.StringPtr(string(hashedPassword)), Username: common.NullableTrimmedString(cmd.Username), Role: model.StringPtr(role), PlanID: cmd.PlanID}
	if err := m.runtime.DB().WithContext(ctx).Create(user).Error; err != nil { if errors.Is(err, gorm.ErrDuplicatedKey) { return nil, status.Error(codes.AlreadyExists, "Email already registered") }; return nil, status.Error(codes.Internal, "Failed to create user") }
	payload, err := m.buildAdminUser(ctx, user)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to create user") }
	return &payload, nil
}

func (m *Module) UpdateAdminUser(ctx context.Context, cmd UpdateAdminUserCommand) (*AdminUserView, error) {
	adminResult, err := m.runtime.RequireAdmin(ctx)
	if err != nil { return nil, err }
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return nil, status.Error(codes.NotFound, "User not found") }
	updates := map[string]any{}
	if cmd.Patch.Email != nil { email := strings.TrimSpace(*cmd.Patch.Email); if email == "" { return nil, status.Error(codes.InvalidArgument, "Email is required") }; updates["email"] = email }
	if cmd.Patch.Username != nil { updates["username"] = common.NullableTrimmedString(cmd.Patch.Username) }
	if cmd.Patch.Role != nil { role := common.NormalizeAdminRoleValue(*cmd.Patch.Role); if !common.IsValidAdminRoleValue(role) { return nil, status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK") }; if id == adminResult.UserID && role != "ADMIN" { return nil, status.Error(codes.InvalidArgument, "Cannot change your own role") }; updates["role"] = role }
	if cmd.Patch.PlanID != nil { planID := *cmd.Patch.PlanID; if err := m.EnsurePlanExists(ctx, planID); err != nil { return nil, err }; updates["plan_id"] = planID }
	if cmd.Patch.Password != nil { if strings.TrimSpace(*cmd.Patch.Password) == "" { return nil, status.Error(codes.InvalidArgument, "Password must not be empty") }; hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*cmd.Patch.Password), bcrypt.DefaultCost); if err != nil { return nil, status.Error(codes.Internal, "Failed to hash password") }; updates["password"] = string(hashedPassword) }
	if len(updates) == 0 { var user model.User; if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.NotFound, "User not found") }; return nil, status.Error(codes.Internal, "Failed to update user") }; payload, err := m.buildAdminUser(ctx, &user); if err != nil { return nil, status.Error(codes.Internal, "Failed to update user") }; return &payload, nil }
	result := m.runtime.DB().WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil { if errors.Is(result.Error, gorm.ErrDuplicatedKey) { return nil, status.Error(codes.AlreadyExists, "Email already registered") }; return nil, status.Error(codes.Internal, "Failed to update user") }
	if result.RowsAffected == 0 { return nil, status.Error(codes.NotFound, "User not found") }
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { return nil, status.Error(codes.Internal, "Failed to update user") }
	payload, err := m.buildAdminUser(ctx, &user)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to update user") }
	return &payload, nil
}

func (m *Module) UpdateAdminUserReferralSettings(ctx context.Context, cmd UpdateReferralSettingsCommand) (*AdminUserDetailView, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil { return nil, err }
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return nil, status.Error(codes.NotFound, "User not found") }
	if cmd.ClearReferrer != nil && *cmd.ClearReferrer && cmd.RefUsername != nil && strings.TrimSpace(*cmd.RefUsername) != "" { return nil, status.Error(codes.InvalidArgument, "Cannot set and clear referrer at the same time") }
	if cmd.ClearReferralRewardBps != nil && *cmd.ClearReferralRewardBps && cmd.ReferralRewardBps != nil { return nil, status.Error(codes.InvalidArgument, "Cannot set and clear referral reward override at the same time") }
	if cmd.ReferralRewardBps != nil { bps := *cmd.ReferralRewardBps; if bps < 0 || bps > 10000 { return nil, status.Error(codes.InvalidArgument, "Referral reward bps must be between 0 and 10000") } }
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.NotFound, "User not found") }; return nil, status.Error(codes.Internal, "Failed to update referral settings") }
	updates := map[string]any{}
	if cmd.RefUsername != nil || (cmd.ClearReferrer != nil && *cmd.ClearReferrer) {
		if common.ReferralRewardProcessed(&user) { return nil, status.Error(codes.InvalidArgument, "Cannot change referrer after reward has been granted") }
		if cmd.ClearReferrer != nil && *cmd.ClearReferrer { updates["referred_by_user_id"] = nil } else if cmd.RefUsername != nil { referrer, err := m.LoadReferralUserByUsernameStrict(ctx, *cmd.RefUsername); if err != nil { return nil, err }; if referrer.ID == user.ID { return nil, status.Error(codes.InvalidArgument, "User cannot refer themselves") }; updates["referred_by_user_id"] = referrer.ID }
	}
	if cmd.ReferralEligible != nil { updates["referral_eligible"] = *cmd.ReferralEligible }
	if cmd.ClearReferralRewardBps != nil && *cmd.ClearReferralRewardBps { updates["referral_reward_bps"] = nil } else if cmd.ReferralRewardBps != nil { updates["referral_reward_bps"] = *cmd.ReferralRewardBps }
	if len(updates) > 0 { result := m.runtime.DB().WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(updates); if result.Error != nil { return nil, status.Error(codes.Internal, "Failed to update referral settings") }; if result.RowsAffected == 0 { return nil, status.Error(codes.NotFound, "User not found") } }
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { return nil, status.Error(codes.Internal, "Failed to update referral settings") }
	var subscription *model.PlanSubscription
	var subscriptionRecord model.PlanSubscription
	if err := m.runtime.DB().WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").First(&subscriptionRecord).Error; err == nil { subscription = &subscriptionRecord } else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) { return nil, status.Error(codes.Internal, "Failed to update referral settings") }
	payload, err := m.buildAdminUserDetail(ctx, &user, subscription)
	if err != nil { return nil, status.Error(codes.Internal, "Failed to update referral settings") }
	return &payload, nil
}

func (m *Module) UpdateAdminUserRole(ctx context.Context, cmd UpdateUserRoleCommand) (string, error) {
	adminResult, err := m.runtime.RequireAdmin(ctx)
	if err != nil { return "", err }
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return "", status.Error(codes.NotFound, "User not found") }
	if id == adminResult.UserID { return "", status.Error(codes.InvalidArgument, "Cannot change your own role") }
	role := common.NormalizeAdminRoleValue(cmd.Role)
	if !common.IsValidAdminRoleValue(role) { return "", status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK") }
	result := m.runtime.DB().WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Update("role", role)
	if result.Error != nil { return "", status.Error(codes.Internal, "Failed to update role") }
	if result.RowsAffected == 0 { return "", status.Error(codes.NotFound, "User not found") }
	return role, nil
}

func (m *Module) DeleteAdminUser(ctx context.Context, cmd DeleteAdminUserCommand) error {
	adminResult, err := m.runtime.RequireAdmin(ctx)
	if err != nil { return err }
	id := strings.TrimSpace(cmd.ID)
	if id == "" { return status.Error(codes.NotFound, "User not found") }
	if id == adminResult.UserID { return status.Error(codes.InvalidArgument, "Cannot delete your own account") }
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return status.Error(codes.NotFound, "User not found") }; return status.Error(codes.Internal, "Failed to find user") }
	err = m.runtime.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error { tables := []struct { model any; where string }{{&model.AdTemplate{}, "user_id = ?"}, {&model.Notification{}, "user_id = ?"}, {&model.Domain{}, "user_id = ?"}, {&model.WalletTransaction{}, "user_id = ?"}, {&model.PlanSubscription{}, "user_id = ?"}, {&model.UserPreference{}, "user_id = ?"}, {&model.Video{}, "user_id = ?"}, {&model.Payment{}, "user_id = ?"}}; for _, item := range tables { if err := tx.Where(item.where, id).Delete(item.model).Error; err != nil { return err } }; return tx.Where("id = ?", id).Delete(&model.User{}).Error })
	if err != nil { return status.Error(codes.Internal, "Failed to delete user") }
	return nil
}

func mapUserPayload(payload *common.UserPayload) *UserView {
	if payload == nil { return nil }
	return &UserView{ID: payload.ID, Email: payload.Email, Username: payload.Username, Avatar: payload.Avatar, Role: payload.Role, GoogleID: payload.GoogleID, StorageUsed: payload.StorageUsed, PlanID: payload.PlanID, PlanStartedAt: payload.PlanStartedAt, PlanExpiresAt: payload.PlanExpiresAt, PlanTermMonths: payload.PlanTermMonths, PlanPaymentMethod: payload.PlanPaymentMethod, PlanExpiringSoon: payload.PlanExpiringSoon, WalletBalance: payload.WalletBalance, Language: payload.Language, Locale: payload.Locale, CreatedAt: payload.CreatedAt, UpdatedAt: payload.UpdatedAt}
}

func mapPreferences(pref *model.UserPreference) *PreferencesView {
	if pref == nil { return nil }
	return &PreferencesView{EmailNotifications: pref.EmailNotifications != nil && *pref.EmailNotifications, PushNotifications: pref.PushNotifications != nil && *pref.PushNotifications, MarketingNotifications: pref.MarketingNotifications, TelegramNotifications: pref.TelegramNotifications, Language: model.StringValue(pref.Language), Locale: model.StringValue(pref.Locale)}
}

func (m *Module) updateUserProfile(ctx context.Context, userID string, req updateProfileInput) (*model.User, error) {
	updates := map[string]any{}
	if req.Username != nil { updates["username"] = strings.TrimSpace(*req.Username) }
	if req.Email != nil { email := strings.TrimSpace(*req.Email); if email == "" { return nil, ErrEmailRequired }; updates["email"] = email }
	if len(updates) > 0 { if err := m.runtime.DB().WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil { if errors.Is(err, gorm.ErrDuplicatedKey) { return nil, ErrEmailAlreadyRegistered }; m.runtime.Logger().Error("Failed to update user", "error", err); return nil, err } }
	pref, err := model.FindOrCreateUserPreference(ctx, m.runtime.DB(), userID)
	if err != nil { m.runtime.Logger().Error("Failed to load user preference", "error", err); return nil, err }
	prefChanged := false
	if req.Language != nil { pref.Language = model.StringPtr(strings.TrimSpace(*req.Language)); prefChanged = true }
	if req.Locale != nil { pref.Locale = model.StringPtr(strings.TrimSpace(*req.Locale)); prefChanged = true }
	if strings.TrimSpace(model.StringValue(pref.Language)) == "" { pref.Language = model.StringPtr("en"); prefChanged = true }
	if strings.TrimSpace(model.StringValue(pref.Locale)) == "" { pref.Locale = model.StringPtr(model.StringValue(pref.Language)); prefChanged = true }
	if prefChanged { if err := m.runtime.DB().WithContext(ctx).Save(pref).Error; err != nil { m.runtime.Logger().Error("Failed to save user preference", "error", err); return nil, err } }
	u := query.User
	user, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
	if err != nil { return nil, err }
	return user, nil
}

func (m *Module) loadUserPreferences(ctx context.Context, userID string) (*model.UserPreference, error) { return model.FindOrCreateUserPreference(ctx, m.runtime.DB(), userID) }

func (m *Module) updateUserPreferences(ctx context.Context, userID string, req updatePreferencesInput) (*model.UserPreference, error) {
	pref, err := model.FindOrCreateUserPreference(ctx, m.runtime.DB(), userID)
	if err != nil { m.runtime.Logger().Error("Failed to load preferences", "error", err); return nil, err }
	if req.EmailNotifications != nil { pref.EmailNotifications = model.BoolPtr(*req.EmailNotifications) }
	if req.PushNotifications != nil { pref.PushNotifications = model.BoolPtr(*req.PushNotifications) }
	if req.MarketingNotifications != nil { pref.MarketingNotifications = *req.MarketingNotifications }
	if req.TelegramNotifications != nil { pref.TelegramNotifications = *req.TelegramNotifications }
	if req.Language != nil { pref.Language = model.StringPtr(strings.TrimSpace(*req.Language)) }
	if req.Locale != nil { pref.Locale = model.StringPtr(strings.TrimSpace(*req.Locale)) }
	if strings.TrimSpace(model.StringValue(pref.Language)) == "" { pref.Language = model.StringPtr("en") }
	if strings.TrimSpace(model.StringValue(pref.Locale)) == "" { pref.Locale = model.StringPtr(model.StringValue(pref.Language)) }
	if err := m.runtime.DB().WithContext(ctx).Save(pref).Error; err != nil { m.runtime.Logger().Error("Failed to save preferences", "error", err); return nil, err }
	return pref, nil
}

func (m *Module) loadUsage(ctx context.Context, user *model.User) (*usagePayload, error) {
	var totalVideos int64
	if err := m.runtime.DB().WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", user.ID).Count(&totalVideos).Error; err != nil { m.runtime.Logger().Error("Failed to count user videos", "error", err, "user_id", user.ID); return nil, err }
	return &usagePayload{UserID: user.ID, TotalVideos: totalVideos, TotalStorage: user.StorageUsed}, nil
}

func (m *Module) buildReferralShareLink(username *string) *string {
	trimmed := strings.TrimSpace(common.StringValue(username))
	if trimmed == "" { return nil }
	path := "/ref/" + trimmed
	base := strings.TrimRight(strings.TrimSpace(m.runtime.FrontendBaseURL()), "/")
	if base == "" { return &path }
	link := base + path
	return &link
}

func (m *Module) loadReferralUsersByUsername(ctx context.Context, username string) ([]model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" { return nil, nil }
	var users []model.User
	if err := m.runtime.DB().WithContext(ctx).Where("LOWER(username) = LOWER(?)", trimmed).Order("created_at ASC, id ASC").Limit(2).Find(&users).Error; err != nil { return nil, err }
	return users, nil
}

func (m *Module) resolveReferralUserByUsername(ctx context.Context, username string) (*model.User, error) {
	users, err := m.loadReferralUsersByUsername(ctx, username)
	if err != nil { return nil, err }
	if len(users) != 1 { return nil, nil }
	return &users[0], nil
}

func (m *Module) buildAdminUser(ctx context.Context, user *model.User) (AdminUserView, error) {
	if user == nil { return AdminUserView{}, nil }
	videoCount, err := m.loadAdminUserVideoCount(ctx, user.ID); if err != nil { return AdminUserView{}, err }
	walletBalance, err := model.GetWalletBalance(ctx, m.runtime.DB(), user.ID); if err != nil { return AdminUserView{}, err }
	planName, err := m.loadAdminPlanName(ctx, user.PlanID); if err != nil { return AdminUserView{}, err }
	return AdminUserView{ID: user.ID, Email: user.Email, Username: common.NullableTrimmedString(user.Username), Avatar: common.NullableTrimmedString(user.Avatar), Role: common.NullableTrimmedString(user.Role), PlanID: common.NullableTrimmedString(user.PlanID), PlanName: planName, StorageUsed: user.StorageUsed, VideoCount: videoCount, WalletBalance: walletBalance, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt}, nil
}

func (m *Module) buildAdminUserDetail(ctx context.Context, user *model.User, subscription *model.PlanSubscription) (AdminUserDetailView, error) {
	payload, err := m.buildAdminUser(ctx, user); if err != nil { return AdminUserDetailView{}, err }
	referral, err := m.buildAdminUserReferralInfo(ctx, user); if err != nil { return AdminUserDetailView{}, err }
	return AdminUserDetailView{User: payload, Subscription: subscription, Referral: referral}, nil
}

func (m *Module) buildAdminUserReferralInfo(ctx context.Context, user *model.User) (*AdminUserReferralInfoView, error) {
	if user == nil { return nil, nil }
	var referrer *ReferralUserSummaryView
	if user.ReferredByUserID != nil && strings.TrimSpace(*user.ReferredByUserID) != "" { loadedReferrer, err := m.loadReferralUserSummary(ctx, strings.TrimSpace(*user.ReferredByUserID)); if err != nil { return nil, err }; referrer = loadedReferrer }
	bps := common.EffectiveReferralRewardBps(user.ReferralRewardBps)
	return &AdminUserReferralInfoView{Referrer: referrer, ReferralEligible: common.ReferralUserEligible(user), EffectiveRewardPercent: common.ReferralRewardBpsToPercent(bps), RewardOverridePercent: func() *float64 { if user.ReferralRewardBps == nil { return nil }; value := common.ReferralRewardBpsToPercent(*user.ReferralRewardBps); return &value }(), ShareLink: m.buildReferralShareLink(user.Username), RewardGranted: common.ReferralRewardProcessed(user), RewardGrantedAt: user.ReferralRewardGrantedAt, RewardPaymentID: common.NullableTrimmedString(user.ReferralRewardPaymentID), RewardAmount: user.ReferralRewardAmount}, nil
}

func (m *Module) loadAdminUserVideoCount(ctx context.Context, userID string) (int64, error) { var videoCount int64; if err := m.runtime.DB().WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", userID).Count(&videoCount).Error; err != nil { return 0, err }; return videoCount, nil }

func (m *Module) loadReferralUserSummary(ctx context.Context, userID string) (*ReferralUserSummaryView, error) {
	if strings.TrimSpace(userID) == "" { return nil, nil }
	var user model.User
	if err := m.runtime.DB().WithContext(ctx).Select("id, email, username").Where("id = ?", userID).First(&user).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, nil }; return nil, err }
	return &ReferralUserSummaryView{ID: user.ID, Email: user.Email, Username: common.NullableTrimmedString(user.Username)}, nil
}

func (m *Module) loadAdminPlanName(ctx context.Context, planID *string) (*string, error) {
	if planID == nil || strings.TrimSpace(*planID) == "" { return nil, nil }
	var plan model.Plan
	if err := m.runtime.DB().WithContext(ctx).Select("id, name").Where("id = ?", *planID).First(&plan).Error; err != nil { if errors.Is(err, gorm.ErrRecordNotFound) { return nil, nil }; return nil, err }
	return common.NullableTrimmedString(&plan.Name), nil
}
