package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/modules/common"
	videodomain "stream.api/internal/video"
)

type Module struct {
	runtime *common.Runtime
}

func New(runtime *common.Runtime) *Module {
	return &Module{runtime: runtime}
}

func (m *Module) ListAdminJobs(ctx context.Context, queryValue ListAdminJobsQuery) (*ListAdminJobsResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	var (
		result *videodomain.PaginatedJobs
		err    error
	)
	cursor := ""
	if queryValue.Cursor != nil {
		cursor = *queryValue.Cursor
	}
	if queryValue.UseCursorPagination {
		result, err = videoService.ListJobsByCursor(ctx, queryValue.AgentID, cursor, queryValue.PageSize)
	} else if queryValue.AgentID != "" {
		result, err = videoService.ListJobsByAgent(ctx, queryValue.AgentID, queryValue.Offset, queryValue.Limit)
	} else {
		result, err = videoService.ListJobs(ctx, queryValue.Offset, queryValue.Limit)
	}
	if err != nil {
		if errors.Is(err, videodomain.ErrInvalidJobCursor) {
			return nil, status.Error(codes.InvalidArgument, "Invalid job cursor")
		}
		return nil, status.Error(codes.Internal, "Failed to list jobs")
	}
	var nextCursor *string
	if strings.TrimSpace(result.NextCursor) != "" {
		value := result.NextCursor
		nextCursor = &value
	}
	return &ListAdminJobsResult{Jobs: result.Jobs, Total: result.Total, Offset: result.Offset, Limit: result.Limit, HasMore: result.HasMore, PageSize: result.PageSize, NextCursor: nextCursor}, nil
}

func (m *Module) GetAdminJob(ctx context.Context, queryValue GetAdminJobQuery) (*videodomain.Job, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	if queryValue.ID == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	job, err := videoService.GetJob(ctx, queryValue.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.Internal, "Failed to load job")
	}
	return job, nil
}

func (m *Module) CreateAdminJob(ctx context.Context, cmd CreateAdminJobCommand) (*videodomain.Job, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	if cmd.Command == "" {
		return nil, status.Error(codes.InvalidArgument, "Command is required")
	}
	image := strings.TrimSpace(cmd.Image)
	if image == "" {
		image = "alpine"
	}
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		name = cmd.Command
	}
	payload, err := json.Marshal(map[string]any{"image": image, "commands": []string{cmd.Command}, "environment": cmd.Env})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create job payload")
	}
	videoID := ""
	if cmd.VideoID != nil {
		videoID = strings.TrimSpace(*cmd.VideoID)
	}
	job, err := videoService.CreateJob(ctx, strings.TrimSpace(cmd.UserID), videoID, name, payload, cmd.Priority, cmd.TimeLimit)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create job")
	}
	return job, nil
}

func (m *Module) CancelAdminJob(ctx context.Context, cmd CancelAdminJobCommand) (*CancelAdminJobResult, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	if err := videoService.CancelJob(ctx, cmd.ID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &CancelAdminJobResult{Status: "cancelled", JobID: cmd.ID}, nil
}

func (m *Module) RetryAdminJob(ctx context.Context, cmd RetryAdminJobCommand) (*videodomain.Job, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	videoService := m.runtime.VideoService()
	if videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}
	if cmd.ID == "" {
		return nil, status.Error(codes.NotFound, "Job not found")
	}
	job, err := videoService.RetryJob(ctx, cmd.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, status.Error(codes.NotFound, "Job not found")
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return job, nil
}

func (m *Module) ListAdminAgents(ctx context.Context) ([]*videodomain.AgentWithStats, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	agentRuntime := m.runtime.AgentRuntime()
	if agentRuntime == nil {
		return nil, status.Error(codes.Unavailable, "Agent runtime is unavailable")
	}
	return agentRuntime.ListAgentsWithStats(), nil
}

func (m *Module) RestartAdminAgent(ctx context.Context, cmd AgentCommand) (string, error) {
	if _, err := m.runtime.RequireAdmin(ctx); err != nil {
		return "", err
	}
	agentRuntime := m.runtime.AgentRuntime()
	if agentRuntime == nil {
		return "", status.Error(codes.Unavailable, "Agent runtime is unavailable")
	}
	if !agentRuntime.SendCommand(strings.TrimSpace(cmd.ID), cmd.Command) {
		return "", status.Error(codes.Unavailable, "Agent not active or command channel full")
	}
	return cmd.Success, nil
}

func (m *Module) UpdateAdminAgent(ctx context.Context, cmd AgentCommand) (string, error) {
	return m.RestartAdminAgent(ctx, cmd)
}
