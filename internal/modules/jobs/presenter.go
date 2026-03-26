package jobs

import (
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
	videodomain "stream.api/internal/video"
)

func presentListAdminJobsResponse(result *ListAdminJobsResult) *appv1.ListAdminJobsResponse {
	jobs := make([]*appv1.AdminJob, 0, len(result.Jobs))
	for _, job := range result.Jobs {
		jobs = append(jobs, common.BuildAdminJob(job))
	}
	response := &appv1.ListAdminJobsResponse{
		Jobs:     jobs,
		Total:    result.Total,
		Offset:   int32(result.Offset),
		Limit:    int32(result.Limit),
		HasMore:  result.HasMore,
		PageSize: int32(result.PageSize),
	}
	if result.NextCursor != nil {
		response.NextCursor = result.NextCursor
	}
	return response
}

func presentGetAdminJobResponse(job *videodomain.Job) *appv1.GetAdminJobResponse {
	return &appv1.GetAdminJobResponse{Job: common.BuildAdminJob(job)}
}

func presentCreateAdminJobResponse(job *videodomain.Job) *appv1.CreateAdminJobResponse {
	return &appv1.CreateAdminJobResponse{Job: common.BuildAdminJob(job)}
}

func presentCancelAdminJobResponse(result *CancelAdminJobResult) *appv1.CancelAdminJobResponse {
	return &appv1.CancelAdminJobResponse{Status: result.Status, JobId: result.JobID}
}

func presentRetryAdminJobResponse(job *videodomain.Job) *appv1.RetryAdminJobResponse {
	return &appv1.RetryAdminJobResponse{Job: common.BuildAdminJob(job)}
}

func presentListAdminAgentsResponse(items []*videodomain.AgentWithStats) *appv1.ListAdminAgentsResponse {
	agents := make([]*appv1.AdminAgent, 0, len(items))
	for _, item := range items {
		agents = append(agents, common.BuildAdminAgent(item))
	}
	return &appv1.ListAdminAgentsResponse{Agents: agents}
}

func presentAgentCommandResponse(status string) *appv1.AdminAgentCommandResponse {
	return &appv1.AdminAgentCommandResponse{Status: status}
}
