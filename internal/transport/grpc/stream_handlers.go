package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	proto "stream.api/internal/api/proto/agent/v1"
	"stream.api/internal/dto"
)

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
				_ = s.jobService.UpdateJobStatus(ctx, job.ID, dto.JobStatusFailure)
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
			if err := stream.Send(&proto.Workflow{Id: job.ID, Timeout: 60 * 60 * 1000, Payload: payload}); err != nil {
				_ = s.jobService.UpdateJobStatus(ctx, job.ID, dto.JobStatusPending)
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
	if err := s.jobService.UpdateJobStatus(ctx, req.Id, dto.JobStatusRunning); err != nil {
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
	jobStatus := dto.JobStatusSuccess
	if req.State != nil && req.State.Error != "" {
		jobStatus = dto.JobStatusFailure
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
