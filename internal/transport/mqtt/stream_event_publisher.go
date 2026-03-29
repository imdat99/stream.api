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

type agentRuntime interface {
	ListAgentsWithStats() []*dto.AgentWithStats
}

type streamEventPublisher struct {
	client     pahomqtt.Client
	jobService *service.JobService
	agentRT    agentRuntime
	logger     logger.Logger
	prefix     string
}

func newStreamEventPublisher(jobService *service.JobService, agentRT agentRuntime, appLogger logger.Logger) (*streamEventPublisher, error) {
	client, err := connectPahoClient(defaultMQTTBrokerURL, fmt.Sprintf("stream-api-%d", time.Now().UnixNano()))
	if err != nil {
		return nil, err
	}

	return &streamEventPublisher{
		client:     client,
		jobService: jobService,
		agentRT:    agentRT,
		logger:     appLogger,
		prefix:     defaultMQTTPrefix,
	}, nil
}

func (p *streamEventPublisher) start(ctx context.Context) {
	if p == nil || p.jobService == nil {
		return
	}
	go p.consumeLogs(ctx)
	go p.consumeJobUpdates(ctx)
	go p.consumeResources(ctx)
}

func (p *streamEventPublisher) consumeLogs(ctx context.Context) {
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
			if err := publishMQTTJSON(p.client, p.logTopic(entry.JobID), entry); err != nil {
				p.logger.Error("Failed to publish MQTT job log", "error", err, "job_id", entry.JobID)
			}
		}
	}
}

func (p *streamEventPublisher) consumeJobUpdates(ctx context.Context) {
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

func (p *streamEventPublisher) consumeResources(ctx context.Context) {
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

func (p *streamEventPublisher) findAgent(agentID string) *dto.AgentWithStats {
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

func (p *streamEventPublisher) publishEvent(eventType string, payload any, jobID string) error {
	message := mqttEvent{Type: eventType, Payload: payload}
	if jobID != "" {
		if err := publishMQTTJSON(p.client, p.jobTopic(jobID), message); err != nil {
			return err
		}
	}
	return publishMQTTJSON(p.client, p.eventsTopic(), message)
}

func (p *streamEventPublisher) logTopic(jobID string) string {
	return fmt.Sprintf("%s/logs/%s", p.prefix, jobID)
}

func (p *streamEventPublisher) jobTopic(jobID string) string {
	return fmt.Sprintf("%s/job/%s", p.prefix, jobID)
}

func (p *streamEventPublisher) eventsTopic() string {
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
