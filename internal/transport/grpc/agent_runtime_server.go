package grpc

import (
	"context"
	"sync"

	grpcpkg "google.golang.org/grpc"
	proto "stream.api/internal/api/proto/agent/v1"
	"stream.api/internal/dto"
	"stream.api/internal/service"
)

type Server struct {
	proto.UnimplementedWoodpeckerServer
	proto.UnimplementedWoodpeckerAuthServer
	jobService   *service.JobService
	agentManager *AgentManager
	agentSecret  string
	sessions     sync.Map
	agentJobs    sync.Map
	onAgentEvent func(string, *dto.AgentWithStats)
}

func NewServer(jobService *service.JobService, agentSecret string) *Server {
	return &Server{jobService: jobService, agentManager: NewAgentManager(), agentSecret: agentSecret}
}

func (s *Server) SetAgentEventHandler(handler func(string, *dto.AgentWithStats)) {
	s.onAgentEvent = handler
}

func (s *Server) Register(grpcServer grpcpkg.ServiceRegistrar) {
	proto.RegisterWoodpeckerServer(grpcServer, s)
	proto.RegisterWoodpeckerAuthServer(grpcServer, s)
}

func (s *Server) SendCommand(agentID string, cmd string) bool {
	return s.agentManager.SendCommand(agentID, cmd)
}

func (s *Server) ListAgents() []*dto.Agent { return s.agentManager.ListAll() }

func (s *Server) ListAgentsWithStats() []*dto.AgentWithStats {
	agents := s.agentManager.ListAll()
	result := make([]*dto.AgentWithStats, 0, len(agents))
	for _, agent := range agents {
		result = append(result, &dto.AgentWithStats{Agent: agent, ActiveJobCount: int64(len(s.getAgentJobs(agent.ID)))})
	}
	return result
}

func (s *Server) getAgentWithStats(agentID string) *dto.AgentWithStats {
	for _, agent := range s.ListAgentsWithStats() {
		if agent != nil && agent.Agent != nil && agent.Agent.ID == agentID {
			return agent
		}
	}
	return nil
}

func (s *Server) Version(context.Context, *proto.Empty) (*proto.VersionResponse, error) {
	return &proto.VersionResponse{GrpcVersion: 15, ServerVersion: "stream.api"}, nil
}
