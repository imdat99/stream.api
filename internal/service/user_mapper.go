package service

import (
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

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
