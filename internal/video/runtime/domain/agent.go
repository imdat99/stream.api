package domain

import "time"

type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusBusy    AgentStatus = "busy"
)

type Agent struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Platform      string      `json:"platform"`
	Backend       string      `json:"backend"`
	Version       string      `json:"version"`
	Capacity      int32       `json:"capacity"`
	Status        AgentStatus `json:"status"`
	CPU           float64     `json:"cpu"`
	RAM           float64     `json:"ram"`
	LastHeartbeat time.Time   `json:"last_heartbeat"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}
