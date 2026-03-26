package service

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
