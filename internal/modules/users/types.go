package users

import (
	"time"

	"stream.api/internal/database/model"
)

type UserView struct {
	ID                string
	Email             string
	Username          *string
	Avatar            *string
	Role              *string
	GoogleID          *string
	StorageUsed       int64
	PlanID            *string
	PlanStartedAt     *time.Time
	PlanExpiresAt     *time.Time
	PlanTermMonths    *int32
	PlanPaymentMethod *string
	PlanExpiringSoon  bool
	WalletBalance     float64
	Language          string
	Locale            string
	CreatedAt         *time.Time
	UpdatedAt         time.Time
}

type PreferencesView struct {
	EmailNotifications     bool
	PushNotifications      bool
	MarketingNotifications bool
	TelegramNotifications  bool
	Language               string
	Locale                 string
}

type UsageView struct {
	UserID       string
	TotalVideos  int64
	TotalStorage int64
}

type NotificationView struct {
	Notification model.Notification
}

type ListNotificationsResult struct {
	Items []NotificationView
}

type UpdateProfileCommand struct {
	UserID   string
	Username *string
	Email    *string
	Language *string
	Locale   *string
}

type UpdatePreferencesCommand struct {
	UserID                  string
	EmailNotifications      *bool
	PushNotifications       *bool
	MarketingNotifications  *bool
	TelegramNotifications   *bool
	Language                *string
	Locale                  *string
}

type MarkNotificationCommand struct {
	UserID string
	ID     string
}

type UserPatch struct {
	Email    *string
	Username *string
	Role     *string
	PlanID   **string
	Password *string
}

type AdminUserView struct {
	ID            string
	Email         string
	Username      *string
	Avatar        *string
	Role          *string
	PlanID        *string
	PlanName      *string
	StorageUsed   int64
	VideoCount    int64
	WalletBalance float64
	CreatedAt     *time.Time
	UpdatedAt     time.Time
}

type ReferralUserSummaryView struct {
	ID       string
	Email    string
	Username *string
}

type AdminUserReferralInfoView struct {
	Referrer              *ReferralUserSummaryView
	ReferralEligible      bool
	EffectiveRewardPercent float64
	RewardOverridePercent *float64
	ShareLink             *string
	RewardGranted         bool
	RewardGrantedAt       *time.Time
	RewardPaymentID       *string
	RewardAmount          *float64
}

type AdminUserDetailView struct {
	User         AdminUserView
	Subscription *model.PlanSubscription
	Referral     *AdminUserReferralInfoView
}

type ListAdminUsersQuery struct {
	Page   int32
	Limit  int32
	Search string
	Role   string
}

type ListAdminUsersResult struct {
	Items []AdminUserView
	Total int64
	Page  int32
	Limit int32
}

type GetAdminUserQuery struct {
	ID string
}

type CreateAdminUserCommand struct {
	Email    string
	Password string
	Username *string
	Role     string
	PlanID   *string
}

type UpdateAdminUserCommand struct {
	ActorUserID string
	ID          string
	Patch       UserPatch
}

type UpdateReferralSettingsCommand struct {
	ID                     string
	RefUsername            *string
	ClearReferrer          *bool
	ReferralEligible       *bool
	ReferralRewardBps      *int32
	ClearReferralRewardBps *bool
}

type UpdateUserRoleCommand struct {
	ActorUserID string
	ID          string
	Role        string
}

type DeleteAdminUserCommand struct {
	ActorUserID string
	ID          string
}
