package jobs

import (
	"context"
	"strings"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	module *Module
}

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) ListAdminJobs(ctx context.Context, req *appv1.ListAdminJobsRequest) (*appv1.ListAdminJobsResponse, error) {
	useCursorPagination := req.Cursor != nil || int(req.GetPageSize()) > 0
	result, err := h.module.ListAdminJobs(ctx, ListAdminJobsQuery{AgentID: strings.TrimSpace(req.GetAgentId()), Offset: int(req.GetOffset()), Limit: int(req.GetLimit()), Cursor: req.Cursor, PageSize: int(req.GetPageSize()), UseCursorPagination: useCursorPagination})
	if err != nil {
		return nil, err
	}
	return presentListAdminJobsResponse(result), nil
}

func (h *Handler) GetAdminJob(ctx context.Context, req *appv1.GetAdminJobRequest) (*appv1.GetAdminJobResponse, error) {
	job, err := h.module.GetAdminJob(ctx, GetAdminJobQuery{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentGetAdminJobResponse(job), nil
}

func (h *Handler) GetAdminJobLogs(ctx context.Context, req *appv1.GetAdminJobLogsRequest) (*appv1.GetAdminJobLogsResponse, error) {
	response, err := h.GetAdminJob(ctx, &appv1.GetAdminJobRequest{Id: req.GetId()})
	if err != nil {
		return nil, err
	}
	return &appv1.GetAdminJobLogsResponse{Logs: response.GetJob().GetLogs()}, nil
}

func (h *Handler) CreateAdminJob(ctx context.Context, req *appv1.CreateAdminJobRequest) (*appv1.CreateAdminJobResponse, error) {
	job, err := h.module.CreateAdminJob(ctx, CreateAdminJobCommand{Command: strings.TrimSpace(req.GetCommand()), Image: strings.TrimSpace(req.GetImage()), Name: strings.TrimSpace(req.GetName()), UserID: strings.TrimSpace(req.GetUserId()), VideoID: req.VideoId, Env: req.GetEnv(), Priority: int(req.GetPriority()), TimeLimit: req.GetTimeLimit()})
	if err != nil {
		return nil, err
	}
	return presentCreateAdminJobResponse(job), nil
}

func (h *Handler) CancelAdminJob(ctx context.Context, req *appv1.CancelAdminJobRequest) (*appv1.CancelAdminJobResponse, error) {
	result, err := h.module.CancelAdminJob(ctx, CancelAdminJobCommand{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentCancelAdminJobResponse(result), nil
}

func (h *Handler) RetryAdminJob(ctx context.Context, req *appv1.RetryAdminJobRequest) (*appv1.RetryAdminJobResponse, error) {
	job, err := h.module.RetryAdminJob(ctx, RetryAdminJobCommand{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentRetryAdminJobResponse(job), nil
}

func (h *Handler) ListAdminAgents(ctx context.Context, _ *appv1.ListAdminAgentsRequest) (*appv1.ListAdminAgentsResponse, error) {
	items, err := h.module.ListAdminAgents(ctx)
	if err != nil {
		return nil, err
	}
	return presentListAdminAgentsResponse(items), nil
}

func (h *Handler) RestartAdminAgent(ctx context.Context, req *appv1.RestartAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	statusValue, err := h.module.RestartAdminAgent(ctx, AgentCommand{ID: strings.TrimSpace(req.GetId()), Command: "restart", Success: "restart command sent"})
	if err != nil {
		return nil, err
	}
	return presentAgentCommandResponse(statusValue), nil
}

func (h *Handler) UpdateAdminAgent(ctx context.Context, req *appv1.UpdateAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	statusValue, err := h.module.UpdateAdminAgent(ctx, AgentCommand{ID: strings.TrimSpace(req.GetId()), Command: "update", Success: "update command sent"})
	if err != nil {
		return nil, err
	}
	return presentAgentCommandResponse(statusValue), nil
}
