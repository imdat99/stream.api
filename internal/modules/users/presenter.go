package users

import (
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

func presentUser(view UserView) *appv1.User {
	return &appv1.User{
		Id:                view.ID,
		Email:             view.Email,
		Username:          view.Username,
		Avatar:            view.Avatar,
		Role:              view.Role,
		GoogleId:          view.GoogleID,
		StorageUsed:       view.StorageUsed,
		PlanId:            view.PlanID,
		PlanStartedAt:     common.TimeToProto(view.PlanStartedAt),
		PlanExpiresAt:     common.TimeToProto(view.PlanExpiresAt),
		PlanTermMonths:    view.PlanTermMonths,
		PlanPaymentMethod: view.PlanPaymentMethod,
		PlanExpiringSoon:  view.PlanExpiringSoon,
		WalletBalance:     view.WalletBalance,
		Language:          view.Language,
		Locale:            view.Locale,
		CreatedAt:         common.TimeToProto(view.CreatedAt),
		UpdatedAt:         common.TimeToProto(&view.UpdatedAt),
	}
}

func presentPreferences(view PreferencesView) *appv1.Preferences {
	return &appv1.Preferences{
		EmailNotifications:     view.EmailNotifications,
		PushNotifications:      view.PushNotifications,
		MarketingNotifications: view.MarketingNotifications,
		TelegramNotifications:  view.TelegramNotifications,
		Language:               view.Language,
		Locale:                 view.Locale,
	}
}

func presentNotification(view NotificationView) *appv1.Notification {
	return common.ToProtoNotification(view.Notification)
}

func presentAdminUser(view AdminUserView) *appv1.AdminUser {
	return &appv1.AdminUser{
		Id:            view.ID,
		Email:         view.Email,
		Username:      view.Username,
		Avatar:        view.Avatar,
		Role:          view.Role,
		PlanId:        view.PlanID,
		PlanName:      view.PlanName,
		StorageUsed:   view.StorageUsed,
		VideoCount:    view.VideoCount,
		WalletBalance: view.WalletBalance,
		CreatedAt:     common.TimeToProto(view.CreatedAt),
		UpdatedAt:     common.TimeToProto(&view.UpdatedAt),
	}
}

func presentReferralSummary(view *ReferralUserSummaryView) *appv1.ReferralUserSummary {
	if view == nil {
		return nil
	}
	return &appv1.ReferralUserSummary{Id: view.ID, Email: view.Email, Username: view.Username}
}

func presentAdminUserReferralInfo(view *AdminUserReferralInfoView) *appv1.AdminUserReferralInfo {
	if view == nil {
		return nil
	}
	return &appv1.AdminUserReferralInfo{
		Referrer:               presentReferralSummary(view.Referrer),
		ReferralEligible:       view.ReferralEligible,
		EffectiveRewardPercent: view.EffectiveRewardPercent,
		RewardOverridePercent:  view.RewardOverridePercent,
		ShareLink:              view.ShareLink,
		RewardGranted:          view.RewardGranted,
		RewardGrantedAt:        common.TimeToProto(view.RewardGrantedAt),
		RewardPaymentId:        view.RewardPaymentID,
		RewardAmount:           view.RewardAmount,
	}
}

func presentAdminUserDetail(view AdminUserDetailView) *appv1.AdminUserDetail {
	return &appv1.AdminUserDetail{
		User:         presentAdminUser(view.User),
		Subscription: common.ToProtoPlanSubscription(view.Subscription),
		Referral:     presentAdminUserReferralInfo(view.Referral),
	}
}
