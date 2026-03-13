package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"stream.api/internal/video/runtime/domain"
	"stream.api/internal/video/runtime/services"
	"stream.api/pkg/logger"
)

const (
	defaultMQTTBrokerURL = "tcp://broker.mqtt-dashboard.com:1883"
	defaultMQTTPrefix    = "picpic"
)

type mqttPublisher struct {
	client     mqtt.Client
	jobService *services.JobService
	agentRT    interface{ ListAgentsWithStats() []*services.AgentWithStats }
	logger     logger.Logger
	prefix     string
}

func newMQTTPublisher(jobService *services.JobService, agentRT interface{ ListAgentsWithStats() []*services.AgentWithStats }, appLogger logger.Logger) (*mqttPublisher, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(defaultMQTTBrokerURL)
	opts.SetClientID(fmt.Sprintf("stream-api-%d", time.Now().UnixNano()))
	opts.SetKeepAlive(60 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetAutoReconnect(true)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	if token.Wait() && token.Error() != nil {
		return nil, token.Error()
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
			payload, _ := json.Marshal(entry)
			p.publish(fmt.Sprintf("%s/logs/%s", p.prefix, entry.JobID), payload)
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
			var inner map[string]any
			if err := json.Unmarshal([]byte(msg), &inner); err != nil {
				continue
			}
			jobID, _ := inner["job_id"].(string)
			eventPayload, _ := json.Marshal(map[string]any{
				"type":    "job_update",
				"payload": inner,
			})
			if jobID != "" {
				p.publish(fmt.Sprintf("%s/job/%s", p.prefix, jobID), eventPayload)
			}
			p.publish(fmt.Sprintf("%s/events", p.prefix), eventPayload)
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
			resourcePayload, _ := json.Marshal(map[string]any{
				"type":    "resource_update",
				"payload": entry,
			})
			p.publish(fmt.Sprintf("%s/events", p.prefix), resourcePayload)
			if p.agentRT != nil {
				for _, agent := range p.agentRT.ListAgentsWithStats() {
					if agent == nil || agent.Agent == nil || agent.ID != entry.AgentID {
						continue
					}
					agentPayload, _ := json.Marshal(map[string]any{
						"type": "agent_update",
						"payload": mapAgentPayload(agent),
					})
					p.publish(fmt.Sprintf("%s/events", p.prefix), agentPayload)
					break
				}
			}
		}
	}
}

func (p *mqttPublisher) publish(topic string, payload []byte) {
	if p == nil || p.client == nil {
		return
	}
	token := p.client.Publish(topic, 0, false, payload)
	token.WaitTimeout(5 * time.Second)
}

func mapAgentPayload(agent *services.AgentWithStats) map[string]any {
	if agent == nil || agent.Agent == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id":             agent.ID,
		"name":           agent.Name,
		"platform":       agent.Platform,
		"backend":        agent.Backend,
		"version":        agent.Version,
		"capacity":       agent.Capacity,
		"status":         string(agent.Status),
		"cpu":            agent.CPU,
		"ram":            agent.RAM,
		"last_heartbeat": agent.LastHeartbeat,
		"created_at":     agent.CreatedAt,
		"updated_at":     agent.UpdatedAt,
		"active_job_count": agent.ActiveJobCount,
	}
}

func publishAgentEvent(client mqtt.Client, appLogger logger.Logger, eventType string, agent *services.AgentWithStats) {
	if client == nil || agent == nil || agent.Agent == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":    eventType,
		"payload": mapAgentPayload(agent),
	})
	if err != nil {
		appLogger.Error("Failed to marshal agent MQTT event", "error", err)
		return
	}
	token := client.Publish(fmt.Sprintf("%s/events", defaultMQTTPrefix), 0, false, payload)
	token.WaitTimeout(5 * time.Second)
}

func publishResourceEvent(client mqtt.Client, appLogger logger.Logger, entry domain.SystemResource) {
	if client == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":    "resource_update",
		"payload": entry,
	})
	if err != nil {
		appLogger.Error("Failed to marshal resource MQTT event", "error", err)
		return
	}
	token := client.Publish(fmt.Sprintf("%s/events", defaultMQTTPrefix), 0, false, payload)
	token.WaitTimeout(5 * time.Second)
}
