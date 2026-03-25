package grpc

import (
	"context"
	"net"

	grpcpkg "google.golang.org/grpc"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/internal/service"
	"stream.api/internal/video"
	runtime "stream.api/internal/video/runtime"
	redisadapter "stream.api/internal/video/runtime/adapters/queue/redis"
	runtimegrpc "stream.api/internal/video/runtime/grpc"
	"stream.api/internal/video/runtime/services"
	"stream.api/pkg/logger"
)

type GRPCModule struct {
	jobService    *services.JobService
	healthService *services.HealthService
	agentRuntime  *runtimegrpc.Server
	mqttPublisher *runtime.MQTTBootstrap
	grpcServer    *grpcpkg.Server
	cfg           *config.Config
}

func NewGRPCModule(ctx context.Context, cfg *config.Config, db *gorm.DB, rds *redisadapter.RedisAdapter, appLogger logger.Logger) (*GRPCModule, error) {
	jobService := services.NewJobService(rds, rds)
	healthService := services.NewHealthService(db, rds.Client(), cfg.Render.ServiceName)
	agentRuntime := runtimegrpc.NewServer(jobService, cfg.Render.AgentSecret)
	videoService := video.NewService(db, jobService)
	grpcServer := grpcpkg.NewServer()

	module := &GRPCModule{
		jobService:    jobService,
		healthService: healthService,
		agentRuntime:  agentRuntime,
		grpcServer:    grpcServer,
		cfg:           cfg,
	}

	if publisher, err := runtime.NewMQTTBootstrap(jobService, agentRuntime, appLogger); err != nil {
		appLogger.Error("Failed to initialize MQTT publisher", "error", err)
	} else {
		module.mqttPublisher = publisher
		agentRuntime.SetAgentEventHandler(func(eventType string, agent *services.AgentWithStats) {
			runtime.PublishAgentMQTTEvent(publisher.Client(), appLogger, eventType, agent)
		})
	}

	agentRuntime.Register(grpcServer)
	service.Register(grpcServer, service.NewServices(rds, db, appLogger, cfg, videoService, agentRuntime))
	if module.mqttPublisher != nil {
		module.mqttPublisher.Start(ctx)
	}

	return module, nil
}

func (m *GRPCModule) JobService() *services.JobService      { return m.jobService }
func (m *GRPCModule) AgentRuntime() *runtimegrpc.Server     { return m.agentRuntime }
func (m *GRPCModule) GRPCServer() *grpcpkg.Server           { return m.grpcServer }
func (m *GRPCModule) GRPCAddress() string                   { return ":" + m.cfg.Server.GRPCPort }
func (m *GRPCModule) ServeGRPC(listener net.Listener) error { return m.grpcServer.Serve(listener) }
func (m *GRPCModule) Shutdown() {
	if m.grpcServer != nil {
		m.grpcServer.GracefulStop()
	}
}
