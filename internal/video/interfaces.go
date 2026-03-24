package video

import (
	"context"

	runtimedomain "stream.api/internal/video/runtime/domain"
	runtimeservices "stream.api/internal/video/runtime/services"
)

type Job = runtimedomain.Job

type AgentWithStats = runtimeservices.AgentWithStats

type PaginatedJobs = runtimeservices.PaginatedJobs

var ErrInvalidJobCursor = runtimeservices.ErrInvalidJobCursor

type JobService interface {
	CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*Job, error)
	ListJobs(ctx context.Context, offset, limit int) (*PaginatedJobs, error)
	ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*PaginatedJobs, error)
	ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*PaginatedJobs, error)
	GetJob(ctx context.Context, id string) (*Job, error)
	CancelJob(ctx context.Context, id string) error
	RetryJob(ctx context.Context, id string) (*Job, error)
	SubscribeJobLogs(ctx context.Context, jobID string) (<-chan runtimedomain.LogEntry, error)
	SubscribeJobUpdates(ctx context.Context) (<-chan string, error)
	SubscribeSystemResources(ctx context.Context) (<-chan runtimedomain.SystemResource, error)
}

type AgentRuntime interface {
	ListAgentsWithStats() []*AgentWithStats
	SendCommand(agentID string, cmd string) bool
}
