package dto

import "stream.api/internal/database/model"

type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusSuccess   JobStatus = "success"
	JobStatusFailure   JobStatus = "failure"
	JobStatusCancelled JobStatus = "cancelled"
)

const (
	DefaultJobPageSize = 20
	MaxJobPageSize     = 100
	JobCursorVersion   = 1
)

type PaginatedJobs struct {
	Jobs       []*model.Job `json:"jobs"`
	Total      int64        `json:"total"`
	Offset     int          `json:"offset"`
	Limit      int          `json:"limit"`
	HasMore    bool         `json:"has_more"`
	NextCursor string       `json:"next_cursor,omitempty"`
	PageSize   int          `json:"page_size"`
}

type JobListCursor struct {
	Version           int    `json:"v"`
	CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
	ID                string `json:"id"`
	AgentID           string `json:"agent_id,omitempty"`
}

type JobConfigEnvelope struct {
	Image       string            `json:"image,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Name        string            `json:"name,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	VideoID     string            `json:"video_id,omitempty"`
	TimeLimit   int64             `json:"time_limit,omitempty"`
}
