package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"stream.api/internal/dto"
	"stream.api/internal/service"
	"stream.api/pkg/logger"
)

const (
	defaultMQTTBrokerURL = "tcp://broker.mqtt-dashboard.com:1883"
	defaultMQTTPrefix    = "picpic"
	defaultPublishWait   = 5 * time.Second
)

type agentRuntime interface {
	ListAgentsWithStats() []*dto.AgentWithStats
}

type mqttPublisher struct {
	client     pahomqtt.Client
	jobService *service.JobService
	agentRT    agentRuntime
	logger     logger.Logger
	prefix     string
}

func newMQTTPublisher(jobService *service.JobService, agentRT agentRuntime, appLogger logger.Logger) (*mqttPublisher, error) {
	client, err := connectPahoClient(defaultMQTTBrokerURL, fmt.Sprintf("stream-api-%d", time.Now().UnixNano()))
	if err != nil {
		return nil, err
	}

	return &mqttPublisher{
		client:     client,
		jobService: jobService,
		agentRT:    agentRT,
		logger:     appLogger,
		prefix:     defaultMQTTPrefix,
	}, nil
}

func (p *mqttPublisher) start(ctx context.Context) {
	if p == nil || p.jobService == nil {
		return
	}
	go p.consumeLogs(ctx)
	go p.consumeJobUpdates(ctx)
	go p.consumeResources(ctx)
}

func (p *mqttPublisher) consumeLogs(ctx context.Context) {
	ch, err := p.jobService.SubscribeJobLogs(ctx, "")
	if err != nil {
		p.logger.Error("Failed to subscribe job logs for MQTT", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			if err := p.publishJSON(p.logTopic(entry.JobID), entry); err != nil {
				p.logger.Error("Failed to publish MQTT job log", "error", err, "job_id", entry.JobID)
			}
		}
	}
}

func (p *mqttPublisher) consumeJobUpdates(ctx context.Context) {
	ch, err := p.jobService.SubscribeJobUpdates(ctx)
	if err != nil {
		p.logger.Error("Failed to subscribe job updates for MQTT", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}

			var payload map[string]any
			if err := json.Unmarshal([]byte(msg), &payload); err != nil {
				p.logger.Error("Failed to decode MQTT job update payload", "error", err)
				continue
			}

			jobID, _ := payload["job_id"].(string)
			if err := p.publishEvent("job_update", payload, jobID); err != nil {
				p.logger.Error("Failed to publish MQTT job update", "error", err, "job_id", jobID)
			}
		}
	}
}

func (p *mqttPublisher) consumeResources(ctx context.Context) {
	ch, err := p.jobService.SubscribeSystemResources(ctx)
	if err != nil {
		p.logger.Error("Failed to subscribe resources for MQTT", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}

			if err := p.publishEvent("resource_update", entry, ""); err != nil {
				p.logger.Error("Failed to publish MQTT resource update", "error", err, "agent_id", entry.AgentID)
			}

			agent := p.findAgent(entry.AgentID)
			if agent == nil {
				continue
			}
			if err := p.publishEvent("agent_update", mapAgentPayload(agent), ""); err != nil {
				p.logger.Error("Failed to publish MQTT agent update", "error", err, "agent_id", entry.AgentID)
			}
		}
	}
}

func (p *mqttPublisher) findAgent(agentID string) *dto.AgentWithStats {
	if p == nil || p.agentRT == nil {
		return nil
	}
	for _, agent := range p.agentRT.ListAgentsWithStats() {
		if agent != nil && agent.Agent != nil && agent.Agent.ID == agentID {
			return agent
		}
	}
	return nil
}

func (p *mqttPublisher) publishEvent(eventType string, payload any, jobID string) error {
	message := mqttEvent{Type: eventType, Payload: payload}
	if jobID != "" {
		if err := p.publishJSON(p.jobTopic(jobID), message); err != nil {
			return err
		}
	}
	return p.publishJSON(p.eventsTopic(), message)
}

func (p *mqttPublisher) publishJSON(topic string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return p.publish(topic, encoded)
}

func (p *mqttPublisher) publish(topic string, payload []byte) error {
	if p == nil {
		return nil
	}
	return publishPahoMessage(p.client, topic, payload)
}

func (p *mqttPublisher) logTopic(jobID string) string {
	return fmt.Sprintf("%s/logs/%s", p.prefix, jobID)
}

func (p *mqttPublisher) jobTopic(jobID string) string {
	return fmt.Sprintf("%s/job/%s", p.prefix, jobID)
}

func (p *mqttPublisher) eventsTopic() string {
	return fmt.Sprintf("%s/events", p.prefix)
}

func mapAgentPayload(agent *dto.AgentWithStats) map[string]any {
	if agent == nil || agent.Agent == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id":               agent.Agent.ID,
		"name":             agent.Name,
		"platform":         agent.Platform,
		"backend":          agent.Backend,
		"version":          agent.Version,
		"capacity":         agent.Capacity,
		"status":           string(agent.Status),
		"cpu":              agent.CPU,
		"ram":              agent.RAM,
		"last_heartbeat":   agent.LastHeartbeat,
		"created_at":       agent.CreatedAt,
		"updated_at":       agent.UpdatedAt,
		"active_job_count": agent.ActiveJobCount,
	}
}

type mqttEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

type MQTTBootstrap struct{ *mqttPublisher }

func NewMQTTBootstrap(jobService *service.JobService, agentRT agentRuntime, appLogger logger.Logger) (*MQTTBootstrap, error) {
	publisher, err := newMQTTPublisher(jobService, agentRT, appLogger)
	if err != nil {
		return nil, err
	}
	return &MQTTBootstrap{mqttPublisher: publisher}, nil
}

func (b *MQTTBootstrap) Start(ctx context.Context) {
	if b == nil || b.mqttPublisher == nil {
		return
	}
	b.mqttPublisher.start(ctx)
}

func (b *MQTTBootstrap) Client() pahomqtt.Client {
	if b == nil || b.mqttPublisher == nil {
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
