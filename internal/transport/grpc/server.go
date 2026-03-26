package grpc

import (
	"context"
	"net"

	grpcpkg "google.golang.org/grpc"
	"gorm.io/gorm"
	redisadapter "stream.api/internal/adapters/redis"
	"stream.api/internal/config"
	"stream.api/internal/dto"
	"stream.api/internal/service"
	"stream.api/internal/transport/mqtt"
	renderworkflow "stream.api/internal/workflow/render"
	"stream.api/pkg/logger"
)

type GRPCModule struct {
	jobService    *service.JobService
	agentRuntime  *Server
	mqttPublisher *mqtt.MQTTBootstrap
	grpcServer    *grpcpkg.Server
	cfg           *config.Config
}

func NewGRPCModule(ctx context.Context, cfg *config.Config, db *gorm.DB, rds *redisadapter.RedisAdapter, appLogger logger.Logger) (*GRPCModule, error) {
	jobService := service.NewJobService(db, rds, rds)
	agentRuntime := NewServer(jobService, cfg.Render.AgentSecret)
	videoService := renderworkflow.New(db, jobService)
	grpcServer := grpcpkg.NewServer()

	module := &GRPCModule{
		jobService:   jobService,
		agentRuntime: agentRuntime,
		grpcServer:   grpcServer,
		cfg:          cfg,
	}

	if publisher, err := mqtt.NewMQTTBootstrap(jobService, agentRuntime, appLogger); err != nil {
		appLogger.Error("Failed to initialize MQTT publisher", "error", err)
	} else {
		module.mqttPublisher = publisher
		agentRuntime.SetAgentEventHandler(func(eventType string, agent *dto.AgentWithStats) {
			mqtt.PublishAgentMQTTEvent(publisher.Client(), appLogger, eventType, agent)
		})
	}

	agentRuntime.Register(grpcServer)
	service.Register(grpcServer, service.NewServices(rds, db, appLogger, cfg, videoService, agentRuntime))
	if module.mqttPublisher != nil {
		module.mqttPublisher.Start(ctx)
	}

	return module, nil
}

func (m *GRPCModule) JobService() *service.JobService       { return m.jobService }
func (m *GRPCModule) AgentRuntime() *Server                 { return m.agentRuntime }
func (m *GRPCModule) GRPCServer() *grpcpkg.Server           { return m.grpcServer }
func (m *GRPCModule) GRPCAddress() string                   { return ":" + m.cfg.Server.GRPCPort }
func (m *GRPCModule) ServeGRPC(listener net.Listener) error { return m.grpcServer.Serve(listener) }
func (m *GRPCModule) Shutdown() {
	if m.grpcServer != nil {
		m.grpcServer.GracefulStop()
	}
}
