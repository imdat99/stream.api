package services

import "stream.api/internal/video/runtime/domain"

type AgentWithStats struct {
	*domain.Agent
	ActiveJobCount int64 `json:"active_job_count"`
}
