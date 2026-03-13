package runtime

import (
	"context"
	"fmt"
	"net"

	grpcpkg "google.golang.org/grpc"
	"gorm.io/gorm"
	"stream.api/internal/config"
	apprpc "stream.api/internal/rpc/app"
	redisadapter "stream.api/internal/video/runtime/adapters/queue/redis"
	runtimegrpc "stream.api/internal/video/runtime/grpc"
	"stream.api/internal/video/runtime/services"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/token"
)

type Module struct {
	ctx           context.Context
	cfg           *config.Config
	jobService    *services.JobService
	healthService *services.HealthService
	grpcServer    *runtimegrpc.Server
	mqttPublisher *mqttPublisher
	grpcRaw       *grpcpkg.Server
}

func NewModule(ctx context.Context, cfg *config.Config, db *gorm.DB, cacheClient cache.Cache, tokenProvider token.Provider, appLogger logger.Logger) (*Module, error) {
	adapter, err := redisadapter.NewAdapter(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		return nil, err
	}
	jobService := services.NewJobService(adapter, adapter)
	healthService := services.NewHealthService(db, adapter.Client(), cfg.Render.ServiceName)
	grpcServer := runtimegrpc.NewServer(jobService, cfg.Render.AgentSecret)
	module := &Module{ctx: ctx, cfg: cfg, jobService: jobService, healthService: healthService, grpcServer: grpcServer, grpcRaw: grpcpkg.NewServer()}
	if publisher, err := newMQTTPublisher(jobService, grpcServer, appLogger); err != nil {
		appLogger.Error("Failed to initialize MQTT publisher", "error", err)
	} else {
		module.mqttPublisher = publisher
		grpcServer.SetAgentEventHandler(func(eventType string, agent *services.AgentWithStats) {
			publishAgentEvent(publisher.client, appLogger, eventType, agent)
		})
	}
	grpcServer.Register(module.grpcRaw)
	apprpc.Register(module.grpcRaw, apprpc.NewServices(cacheClient, tokenProvider, db, appLogger, cfg, jobService, grpcServer))
	if module.mqttPublisher != nil {
		module.mqttPublisher.start(ctx)
	}
	return module, nil
}

func (m *Module) JobService() *services.JobService { return m.jobService }

func (m *Module) AgentRuntime() *runtimegrpc.Server { return m.grpcServer }

func (m *Module) GRPCServer() *grpcpkg.Server { return m.grpcRaw }

func (m *Module) GRPCAddress() string {
	return fmt.Sprintf(":%s", m.cfg.Server.GRPCPort)
}

func (m *Module) ServeGRPC(listener net.Listener) error {
	return m.grpcRaw.Serve(listener)
}

func (m *Module) Shutdown() {
	if m.grpcRaw != nil {
		m.grpcRaw.GracefulStop()
	}
}
