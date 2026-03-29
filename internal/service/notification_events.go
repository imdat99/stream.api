package service

import (
	"context"
	"encoding/json"
	"time"

	"stream.api/internal/database/model"
)

type noopNotificationEventPublisher struct{}

func (noopNotificationEventPublisher) PublishNotificationCreated(context.Context, *model.Notification) error {
	return nil
}

type NotificationCreatedPayload struct {
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	Type        string  `json:"type"`
	Title       string  `json:"title"`
	Message     string  `json:"message"`
	ActionURL   *string `json:"action_url,omitempty"`
	ActionLabel *string `json:"action_label,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
}

func (s *appServices) publishNotificationCreated(ctx context.Context, notification *model.Notification) {
	if s == nil || s.notificationEvents == nil || notification == nil {
		return
	}
	if err := s.notificationEvents.PublishNotificationCreated(ctx, notification); err != nil {
		s.logger.Error("Failed to publish notification MQTT event", "error", err, "notification_id", notification.ID, "user_id", notification.UserID)
	}
}

func BuildNotificationCreatedPayload(notification *model.Notification) NotificationCreatedPayload {
	createdAt := ""
	if notification != nil && notification.CreatedAt != nil {
		createdAt = notification.CreatedAt.UTC().Format(time.RFC3339)
	}
	return NotificationCreatedPayload{
		ID:          notification.ID,
		UserID:      notification.UserID,
		Type:        notification.Type,
		Title:       notification.Title,
		Message:     notification.Message,
		ActionURL:   nullableTrimmedString(notification.ActionURL),
		ActionLabel: nullableTrimmedString(notification.ActionLabel),
		CreatedAt:   createdAt,
	}
}

func mustMarshalNotificationPayload(notification *model.Notification) []byte {
	encoded, _ := json.Marshal(BuildNotificationCreatedPayload(notification))
	return encoded
}
