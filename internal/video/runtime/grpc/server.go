package grpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"stream.api/internal/video/runtime/domain"
	"stream.api/internal/video/runtime/proto"
	"stream.api/internal/video/runtime/services"
)

type Server struct {
	proto.UnimplementedWoodpeckerServer
	proto.UnimplementedWoodpeckerAuthServer
	jobService   *services.JobService
	agentManager *AgentManager
	agentSecret  string
	sessions     sync.Map
	agentJobs    sync.Map
	onAgentEvent func(string, *services.AgentWithStats)
}

func NewServer(jobService *services.JobService, agentSecret string) *Server {
	return &Server{jobService: jobService, agentManager: NewAgentManager(), agentSecret: agentSecret}
}

func (s *Server) SetAgentEventHandler(handler func(string, *services.AgentWithStats)) {
	s.onAgentEvent = handler
}

func (s *Server) Register(grpcServer grpcpkg.ServiceRegistrar) {
	proto.RegisterWoodpeckerServer(grpcServer, s)
	proto.RegisterWoodpeckerAuthServer(grpcServer, s)
}

func (s *Server) SendCommand(agentID string, cmd string) bool {
	return s.agentManager.SendCommand(agentID, cmd)
}

func (s *Server) ListAgents() []*domain.Agent { return s.agentManager.ListAll() }

func (s *Server) ListAgentsWithStats() []*services.AgentWithStats {
	agents := s.agentManager.ListAll()
	result := make([]*services.AgentWithStats, 0, len(agents))
	for _, agent := range agents {
		result = append(result, &services.AgentWithStats{Agent: agent, ActiveJobCount: int64(len(s.getAgentJobs(agent.ID)))})
	}
	return result
}

func (s *Server) getAgentWithStats(agentID string) *services.AgentWithStats {
	for _, agent := range s.ListAgentsWithStats() {
		if agent != nil && agent.Agent != nil && agent.ID == agentID {
			return agent
		}
	}
	return nil
}

func (s *Server) Version(context.Context, *proto.Empty) (*proto.VersionResponse, error) {
	return &proto.VersionResponse{GrpcVersion: 15, ServerVersion: "stream.api"}, nil
}

func generateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAgentID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func (s *Server) getAgentIDFromContext(ctx context.Context) (string, string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", false
	}
	tokens := md.Get("token")
	if len(tokens) == 0 {
		return "", "", false
	}
	token := tokens[0]
	if id, ok := s.sessions.Load(token); ok {
		return id.(string), token, true
	}
	return "", "", false
}

func (s *Server) Next(context.Context, *proto.NextRequest) (*proto.NextResponse, error) {
	return nil, status.Error(codes.Unimplemented, "use StreamJobs")
}

func (s *Server) StreamJobs(_ *proto.StreamOptions, stream grpcpkg.ServerStreamingServer[proto.Workflow]) error {
	ctx := stream.Context()
	agentID, _, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "invalid or missing token")
	}
	s.agentManager.UpdateHeartbeat(agentID)
	cancelCh, _ := s.jobService.SubscribeCancel(ctx, agentID)
	commandCh, _ := s.agentManager.GetCommandChannel(agentID)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case cmd := <-commandCh:
			payload, _ := json.Marshal(map[string]any{"image": "alpine", "commands": []string{"echo 'System Command'"}, "environment": map[string]string{}, "action": cmd})
			if err := stream.Send(&proto.Workflow{Id: fmt.Sprintf("cmd-%s-%d", agentID, time.Now().UnixNano()), Timeout: 300, Payload: payload}); err != nil {
				return err
			}
		case jobID := <-cancelCh:
			if s.isJobAssigned(agentID, jobID) {
				if err := stream.Send(&proto.Workflow{Id: jobID, Cancel: true}); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.agentManager.UpdateHeartbeat(agentID)
			jobCtx, cancel := context.WithTimeout(ctx, time.Second)
			job, err := s.jobService.GetNextJob(jobCtx)
			cancel()
			if err != nil || job == nil {
				continue
			}
			s.trackJobAssignment(agentID, job.ID)
			if err := s.jobService.AssignJob(ctx, job.ID, agentID); err != nil {
				s.untrackJobAssignment(agentID, job.ID)
				continue
			}
			var config map[string]any
			if err := json.Unmarshal([]byte(*job.Config), &config); err != nil {
				_ = s.jobService.UpdateJobStatus(ctx, job.ID, domain.JobStatusFailure)
				s.untrackJobAssignment(agentID, job.ID)
				continue
			}
			image, _ := config["image"].(string)
			if image == "" {
				image = "alpine"
			}
			commands := []string{"echo 'No commands specified'"}
			if raw, ok := config["commands"].([]any); ok && len(raw) > 0 {
				commands = commands[:0]
				for _, item := range raw {
					if text, ok := item.(string); ok {
						commands = append(commands, text)
					}
				}
				if len(commands) == 0 {
					commands = []string{"echo 'No commands specified'"}
				}
			}
			payload, _ := json.Marshal(map[string]any{"image": image, "commands": commands, "environment": map[string]string{}})
			// Sau này xem xét có cần cho job.TimeLimit vào db không?
			// Hiện tại để đơn giản thì cứ để mặc định timeout 1h, nếu job nào cần timeout ngắn hơn thì tự lo trong commands của nó
			if err := stream.Send(&proto.Workflow{Id: job.ID, Timeout: 60 * 60 * 1000, Payload: payload}); err != nil {
				_ = s.jobService.UpdateJobStatus(ctx, job.ID, domain.JobStatusPending)
				s.untrackJobAssignment(agentID, job.ID)
				return err
			}
		}
	}
}

func (s *Server) SubmitStatus(stream grpcpkg.ClientStreamingServer[proto.StatusUpdate, proto.Empty]) error {
	ctx := stream.Context()
	agentID, _, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "invalid or missing token")
	}
	for {
		update, err := stream.Recv()
		if err != nil {
			return stream.SendAndClose(&proto.Empty{})
		}
		switch update.Type {
		case 0, 1:
			_ = s.jobService.ProcessLog(ctx, update.StepUuid, update.Data)
		case 4:
			var progress float64
			fmt.Sscanf(string(update.Data), "%f", &progress)
			_ = s.jobService.UpdateJobProgress(ctx, update.StepUuid, progress)
		case 5:
			var stats struct {
				CPU float64 `json:"cpu"`
				RAM float64 `json:"ram"`
			}
			if json.Unmarshal(update.Data, &stats) == nil {
				s.agentManager.UpdateResources(agentID, stats.CPU, stats.RAM)
				if s.onAgentEvent != nil {
					s.onAgentEvent("agent_update", s.getAgentWithStats(agentID))
				}
			}
			_ = s.jobService.PublishSystemResources(ctx, agentID, update.Data)
		}
	}
}

func (s *Server) Init(ctx context.Context, req *proto.InitRequest) (*proto.Empty, error) {
	if err := s.jobService.UpdateJobStatus(ctx, req.Id, domain.JobStatusRunning); err != nil {
		return nil, status.Error(codes.Internal, "failed to update job status")
	}
	return &proto.Empty{}, nil
}

func (s *Server) Wait(context.Context, *proto.WaitRequest) (*proto.WaitResponse, error) {
	return &proto.WaitResponse{Canceled: false}, nil
}

func (s *Server) Done(ctx context.Context, req *proto.DoneRequest) (*proto.Empty, error) {
	agentID, _, ok := s.getAgentIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	jobStatus := domain.JobStatusSuccess
	if req.State != nil && req.State.Error != "" {
		jobStatus = domain.JobStatusFailure
	}
	if err := s.jobService.UpdateJobStatus(ctx, req.Id, jobStatus); err != nil {
		return nil, status.Error(codes.Internal, "failed to update job status")
	}
	s.untrackJobAssignment(agentID, req.Id)
	return &proto.Empty{}, nil
}

func (s *Server) Update(context.Context, *proto.UpdateRequest) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

func (s *Server) Log(ctx context.Context, req *proto.LogRequest) (*proto.Empty, error) {
	if _, _, ok := s.getAgentIDFromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	for _, entry := range req.LogEntries {
		if entry.StepUuid != "" {
			_ = s.jobService.ProcessLog(ctx, entry.StepUuid, entry.Data)
		}
	}
	return &proto.Empty{}, nil
}

func (s *Server) Extend(context.Context, *proto.ExtendRequest) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

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
		_ = s.jobService.UpdateJobStatus(ctx, jobID, domain.JobStatusFailure)
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

func (s *Server) Auth(ctx context.Context, req *proto.AuthRequest) (*proto.AuthResponse, error) {
	if s.agentSecret != "" && req.AgentToken != s.agentSecret {
		return nil, status.Error(codes.Unauthenticated, "invalid agent secret")
	}
	agentID := req.AgentId
	if len(agentID) > 6 && agentID[:6] == "agent-" {
		agentID = agentID[6:]
	}
	if agentID == "" {
		agentID = generateAgentID()
	}
	accessToken := generateToken()
	s.sessions.Store(accessToken, agentID)
	return &proto.AuthResponse{Status: "ok", AgentId: agentID, AccessToken: accessToken}, nil
}

func (s *Server) trackJobAssignment(agentID, jobID string) {
	jobSetInterface, _ := s.agentJobs.LoadOrStore(agentID, &sync.Map{})
	if jobSet, ok := jobSetInterface.(*sync.Map); ok {
		jobSet.Store(jobID, true)
	}
}

func (s *Server) untrackJobAssignment(agentID, jobID string) {
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			jobSet.Delete(jobID)
		}
	}
}

func (s *Server) isJobAssigned(agentID, jobID string) bool {
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			_, found := jobSet.Load(jobID)
			return found
		}
	}
	return false
}

func (s *Server) getAgentJobs(agentID string) []string {
	jobs := []string{}
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			jobSet.Range(func(key, _ any) bool {
				if jobID, ok := key.(string); ok {
					jobs = append(jobs, jobID)
				}
				return true
			})
		}
	}
	return jobs
}
