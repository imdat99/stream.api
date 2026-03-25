package video

import (
	runtimeservices "stream.api/internal/video/runtime/services"
)

type AgentWithStats = runtimeservices.AgentWithStats

type PaginatedJobs = runtimeservices.PaginatedJobs

var ErrInvalidJobCursor = runtimeservices.ErrInvalidJobCursor

type AgentRuntime interface {
	ListAgentsWithStats() []*AgentWithStats
	SendCommand(agentID string, cmd string) bool
}
