package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/video/runtime/services"
)

func (s *appServices) ListAdminJobs(ctx context.Context, req *appv1.ListAdminJobsRequest) (*appv1.ListAdminJobsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.jobService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	offset := int(req.GetOffset())
	limit := int(req.GetLimit())
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var (
		result *services.PaginatedJobs
		err    error
	)
	if agentID := strings.TrimSpace(req.GetAgentId()); agentID != "" {
		result, err = s.jobService.ListJobsByAgent(ctx, agentID, offset, limit)
	} else {
		result, err = s.jobService.ListJobs(ctx, offset, limit)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to list jobs")
	}

	jobs := make([]*appv1.AdminJob, 0, len(result.Jobs))
	for _, job := range result.Jobs {
		jobs = append(jobs, buildAdminJob(job))
	}

	return &appv1.ListAdminJobsResponse{
		Jobs:    jobs,
		Total:   result.Total,
		Offset:  int32(result.Offset),
		Limit:   int32(result.Limit),
		HasMore: result.HasMore,
	}, nil
}
func (s *appServices) GetAdminJob(ctx context.Context, req *appv1.GetAdminJobRequest) (*appv1.GetAdminJobResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.jobService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	job, err := s.jobService.GetJob(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load job")
	}
	return &appv1.GetAdminJobResponse{Job: buildAdminJob(job)}, nil
}
func (s *appServices) GetAdminJobLogs(ctx context.Context, req *appv1.GetAdminJobLogsRequest) (*appv1.GetAdminJobLogsResponse, error) {
	response, err := s.GetAdminJob(ctx, &appv1.GetAdminJobRequest{Id: req.GetId()})
	if err != nil {
		return nil, err
	}
	return &appv1.GetAdminJobLogsResponse{Logs: response.GetJob().GetLogs()}, nil
}
func (s *appServices) CreateAdminJob(ctx context.Context, req *appv1.CreateAdminJobRequest) (*appv1.CreateAdminJobResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.jobService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	command := strings.TrimSpace(req.GetCommand())
	if command == "" {
		return nil, status.Error(codes.InvalidArgument, "Command is required")
	}
	image := strings.TrimSpace(req.GetImage())
	if image == "" {
		image = "alpine"
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		name = command
	}
	payload, err := json.Marshal(map[string]any{
		"image":       image,
		"commands":    []string{command},
		"environment": req.GetEnv(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create job payload")
	}

	job, err := s.jobService.CreateJob(ctx, strings.TrimSpace(req.GetUserId()), name, payload, int(req.GetPriority()), req.GetTimeLimit())
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create job")
	}
	return &appv1.CreateAdminJobResponse{Job: buildAdminJob(job)}, nil
}
func (s *appServices) CancelAdminJob(ctx context.Context, req *appv1.CancelAdminJobRequest) (*appv1.CancelAdminJobResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.jobService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	if err := s.jobService.CancelJob(ctx, id); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &appv1.CancelAdminJobResponse{Status: "cancelled", JobId: id}, nil
}
func (s *appServices) RetryAdminJob(ctx context.Context, req *appv1.RetryAdminJobRequest) (*appv1.RetryAdminJobResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.jobService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	job, err := s.jobService.RetryJob(ctx, id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &appv1.RetryAdminJobResponse{Job: buildAdminJob(job)}, nil
}
func (s *appServices) ListAdminAgents(ctx context.Context, _ *appv1.ListAdminAgentsRequest) (*appv1.ListAdminAgentsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.agentRuntime == nil {
		return nil, status.Error(codes.Unavailable, "Agent runtime is unavailable")
	}

	items := s.agentRuntime.ListAgentsWithStats()
	agents := make([]*appv1.AdminAgent, 0, len(items))
	for _, item := range items {
		agents = append(agents, buildAdminAgent(item))
	}
	return &appv1.ListAdminAgentsResponse{Agents: agents}, nil
}
func (s *appServices) RestartAdminAgent(ctx context.Context, req *appv1.RestartAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.agentRuntime == nil {
		return nil, status.Error(codes.Unavailable, "Agent runtime is unavailable")
	}
	if !s.agentRuntime.SendCommand(strings.TrimSpace(req.GetId()), "restart") {
		return nil, status.Error(codes.Unavailable, "Agent not active or command channel full")
	}
	return &appv1.AdminAgentCommandResponse{Status: "restart command sent"}, nil
}
func (s *appServices) UpdateAdminAgent(ctx context.Context, req *appv1.UpdateAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.agentRuntime == nil {
		return nil, status.Error(codes.Unavailable, "Agent runtime is unavailable")
	}
	if !s.agentRuntime.SendCommand(strings.TrimSpace(req.GetId()), "update") {
		return nil, status.Error(codes.Unavailable, "Agent not active or command channel full")
	}
	return &appv1.AdminAgentCommandResponse{Status: "update command sent"}, nil
}
