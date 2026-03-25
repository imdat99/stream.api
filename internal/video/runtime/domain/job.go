package domain

type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusSuccess   JobStatus = "success"
	JobStatusFailure   JobStatus = "failure"
	JobStatusCancelled JobStatus = "cancelled"
)
