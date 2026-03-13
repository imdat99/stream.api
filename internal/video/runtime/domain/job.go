package domain

import "time"

type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusSuccess   JobStatus = "success"
	JobStatusFailure   JobStatus = "failure"
	JobStatusCancelled JobStatus = "cancelled"
)

type Job struct {
	ID            string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Status        JobStatus `json:"status" gorm:"type:varchar(32);index"`
	Priority      int       `json:"priority" gorm:"default:0;index"`
	UserID        string    `json:"user_id" gorm:"index"`
	Name          string    `json:"name"`
	TimeLimit     int64     `json:"time_limit"`
	InputURL      string    `json:"input_url"`
	OutputURL     string    `json:"output_url"`
	TotalDuration int64     `json:"total_duration"`
	CurrentTime   int64     `json:"current_time"`
	Progress      float64   `json:"progress"`
	AgentID       *string   `json:"agent_id" gorm:"type:uuid;index"`
	Logs          string    `json:"logs" gorm:"type:text"`
	Config        string    `json:"config" gorm:"type:text"`
	Cancelled     bool      `json:"cancelled" gorm:"default:false"`
	RetryCount    int       `json:"retry_count" gorm:"default:0"`
	MaxRetries    int       `json:"max_retries" gorm:"default:3"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (Job) TableName() string { return "render_jobs" }
