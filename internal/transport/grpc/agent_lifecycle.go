package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	proto "stream.api/internal/api/proto/agent/v1"
	"stream.api/internal/dto"
)

func (s *Server) RegisterAgent(ctx context.Context, req *proto.RegisterAgentRequest) (*proto.RegisterAgentResponse, error) {
	if req.Info == nil {
		return nil, status.Error(codes.InvalidArgument, "connection info is required")
	}
	id, _, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	hostname := ""
	if req.Info.CustomLabels != nil {
		hostname = req.Info.CustomLabels["hostname"]
	}
	name := hostname
	if name == "" {
		name = fmt.Sprintf("agent-%s", id)
	}
	s.agentManager.Register(id, name, req.Info.Platform, req.Info.Backend, req.Info.Version, req.Info.Capacity)
	if s.onAgentEvent != nil {
		s.onAgentEvent("agent_update", s.getAgentWithStats(id))
	}
	return &proto.RegisterAgentResponse{AgentId: id}, nil
}

func (s *Server) UnregisterAgent(ctx context.Context, _ *proto.Empty) (*proto.Empty, error) {
	agentID, token, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	for _, jobID := range s.getAgentJobs(agentID) {
		_ = s.jobService.UpdateJobStatus(ctx, jobID, dto.JobStatusFailure)
		s.untrackJobAssignment(agentID, jobID)
	}
	s.sessions.Delete(token)
	s.agentJobs.Delete(agentID)
	agent := s.getAgentWithStats(agentID)
	s.agentManager.Unregister(agentID)
	if s.onAgentEvent != nil {
		s.onAgentEvent("agent_update", agent)
	}
	return &proto.Empty{}, nil
}

func (s *Server) ReportHealth(ctx context.Context, _ *proto.ReportHealthRequest) (*proto.Empty, error) {
	agentID, _, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	s.agentManager.UpdateHeartbeat(agentID)
	return &proto.Empty{}, nil
}
