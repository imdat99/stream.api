package users

import (
	"context"
	"strings"

	appv1 "stream.api/internal/gen/proto/app/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type AccountHandler struct {
	appv1.UnimplementedAccountServiceServer
	module *Module
}

type PreferencesHandler struct {
	appv1.UnimplementedPreferencesServiceServer
	module *Module
}

type UsageHandler struct {
	appv1.UnimplementedUsageServiceServer
	module *Module
}

type NotificationsHandler struct {
	appv1.UnimplementedNotificationsServiceServer
	module *Module
}

var _ appv1.AccountServiceServer = (*AccountHandler)(nil)
var _ appv1.PreferencesServiceServer = (*PreferencesHandler)(nil)
var _ appv1.UsageServiceServer = (*UsageHandler)(nil)
var _ appv1.NotificationsServiceServer = (*NotificationsHandler)(nil)

func NewAccountHandler(module *Module) *AccountHandler { return &AccountHandler{module: module} }
func NewPreferencesHandler(module *Module) *PreferencesHandler { return &PreferencesHandler{module: module} }
func NewUsageHandler(module *Module) *UsageHandler { return &UsageHandler{module: module} }
func NewNotificationsHandler(module *Module) *NotificationsHandler { return &NotificationsHandler{module: module} }

func (h *AccountHandler) GetMe(ctx context.Context, _ *appv1.GetMeRequest) (*appv1.GetMeResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.GetMe(ctx, result.UserID)
	if err != nil { return nil, err }
	return &appv1.GetMeResponse{User: presentUser(*payload)}, nil
}

func (h *AccountHandler) GetUserById(ctx context.Context, req *wrapperspb.StringValue) (*appv1.User, error) {
	payload, err := h.module.GetUserByID(ctx, req)
	if err != nil { return nil, err }
	return presentUser(*payload), nil
}

func (h *AccountHandler) UpdateMe(ctx context.Context, req *appv1.UpdateMeRequest) (*appv1.UpdateMeResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.UpdateMe(ctx, UpdateProfileCommand{UserID: result.UserID, Username: req.Username, Email: req.Email, Language: req.Language, Locale: req.Locale})
	if err != nil { return nil, err }
	return &appv1.UpdateMeResponse{User: presentUser(*payload)}, nil
}

func (h *AccountHandler) DeleteMe(ctx context.Context, _ *appv1.DeleteMeRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.DeleteMe(ctx, result.UserID); err != nil { return nil, err }
	return commonMessage("Account deleted successfully"), nil
}

func (h *AccountHandler) ClearMyData(ctx context.Context, _ *appv1.ClearMyDataRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.ClearMyData(ctx, result.UserID); err != nil { return nil, err }
	return commonMessage("Data cleared successfully"), nil
}

func (h *PreferencesHandler) GetPreferences(ctx context.Context, _ *appv1.GetPreferencesRequest) (*appv1.GetPreferencesResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.GetPreferences(ctx, result.UserID)
	if err != nil { return nil, err }
	return &appv1.GetPreferencesResponse{Preferences: presentPreferences(*payload)}, nil
}

func (h *PreferencesHandler) UpdatePreferences(ctx context.Context, req *appv1.UpdatePreferencesRequest) (*appv1.UpdatePreferencesResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.UpdatePreferences(ctx, UpdatePreferencesCommand{UserID: result.UserID, EmailNotifications: req.EmailNotifications, PushNotifications: req.PushNotifications, MarketingNotifications: req.MarketingNotifications, TelegramNotifications: req.TelegramNotifications, Language: req.Language, Locale: req.Locale})
	if err != nil { return nil, err }
	return &appv1.UpdatePreferencesResponse{Preferences: presentPreferences(*payload)}, nil
}

func (h *UsageHandler) GetUsage(ctx context.Context, _ *appv1.GetUsageRequest) (*appv1.GetUsageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.GetUsage(ctx, result.User)
	if err != nil { return nil, err }
	return &appv1.GetUsageResponse{UserId: payload.UserID, TotalVideos: payload.TotalVideos, TotalStorage: payload.TotalStorage}, nil
}

func (h *NotificationsHandler) ListNotifications(ctx context.Context, _ *appv1.ListNotificationsRequest) (*appv1.ListNotificationsResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	payload, err := h.module.ListNotifications(ctx, result.UserID)
	if err != nil { return nil, err }
	items := make([]*appv1.Notification, 0, len(payload.Items))
	for _, item := range payload.Items { items = append(items, presentNotification(item)) }
	return &appv1.ListNotificationsResponse{Notifications: items}, nil
}

func (h *NotificationsHandler) MarkNotificationRead(ctx context.Context, req *appv1.MarkNotificationReadRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.MarkNotificationRead(ctx, MarkNotificationCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())}); err != nil { return nil, err }
	return commonMessage("Notification updated"), nil
}

func (h *NotificationsHandler) MarkAllNotificationsRead(ctx context.Context, _ *appv1.MarkAllNotificationsReadRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.MarkAllNotificationsRead(ctx, result.UserID); err != nil { return nil, err }
	return commonMessage("All notifications marked as read"), nil
}

func (h *NotificationsHandler) DeleteNotification(ctx context.Context, req *appv1.DeleteNotificationRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.DeleteNotification(ctx, MarkNotificationCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())}); err != nil { return nil, err }
	return commonMessage("Notification deleted"), nil
}

func (h *NotificationsHandler) ClearNotifications(ctx context.Context, _ *appv1.ClearNotificationsRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil { return nil, err }
	if err := h.module.ClearNotifications(ctx, result.UserID); err != nil { return nil, err }
	return commonMessage("All notifications deleted"), nil
}

func commonMessage(message string) *appv1.MessageResponse { return &appv1.MessageResponse{Message: message} }
