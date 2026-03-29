package mqtt

import (
	"context"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"stream.api/internal/dto"
	"stream.api/internal/service"
	"stream.api/pkg/logger"
)

type MQTTBootstrap struct{ *streamEventPublisher }

func NewMQTTBootstrap(jobService *service.JobService, agentRT agentRuntime, appLogger logger.Logger) (*MQTTBootstrap, error) {
	publisher, err := newStreamEventPublisher(jobService, agentRT, appLogger)
	if err != nil {
		return nil, err
	}
	return &MQTTBootstrap{streamEventPublisher: publisher}, nil
}

func (b *MQTTBootstrap) Start(ctx context.Context) {
	if b == nil || b.streamEventPublisher == nil {
		return
	}
	b.streamEventPublisher.start(ctx)
}

func (b *MQTTBootstrap) Client() pahomqtt.Client {
	if b == nil || b.streamEventPublisher == nil {
		return nil
	}
	return b.client
}

func PublishAgentMQTTEvent(client pahomqtt.Client, appLogger logger.Logger, eventType string, agent *dto.AgentWithStats) {
	publishMQTTEvent(client, appLogger, defaultMQTTPrefix, mqttEvent{
		Type:    eventType,
		Payload: mapAgentPayload(agent),
	})
}
