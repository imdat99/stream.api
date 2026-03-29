package mqtt

import (
	"context"
	"fmt"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"stream.api/internal/database/model"
	"stream.api/internal/service"
	"stream.api/pkg/logger"
)

type notificationPublisher struct {
	client pahomqtt.Client
	logger logger.Logger
	prefix string
}

func NewNotificationPublisher(client pahomqtt.Client, appLogger logger.Logger) service.NotificationEventPublisher {
	if client == nil {
		return service.NotificationEventPublisher(serviceNotificationNoop{})
	}
	return &notificationPublisher{client: client, logger: appLogger, prefix: defaultMQTTPrefix}
}

type serviceNotificationNoop struct{}

func (serviceNotificationNoop) PublishNotificationCreated(context.Context, *model.Notification) error { return nil }

func (p *notificationPublisher) PublishNotificationCreated(_ context.Context, notification *model.Notification) error {
	if p == nil || notification == nil {
		return nil
	}
	message := mqttEvent{
		Type:    "notification.created",
		Payload: service.BuildNotificationCreatedPayload(notification),
	}
	return publishMQTTJSON(p.client, p.notificationTopic(notification.UserID), message)
}

func (p *notificationPublisher) notificationTopic(userID string) string {
	return fmt.Sprintf("%s/notifications/%s", p.prefix, userID)
}

