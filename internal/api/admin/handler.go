//go:build ignore
// +build ignore

package admin

import (
	"gorm.io/gorm"
	runtimegrpc "stream.api/internal/video/runtime/grpc"
	"stream.api/internal/video/runtime/services"
	"stream.api/pkg/logger"
)

type RenderRuntime interface {
	JobService() *services.JobService
	AgentRuntime() *runtimegrpc.Server
}

type Handler struct {
	logger  logger.Logger
	db      *gorm.DB
	runtime RenderRuntime
}

func NewHandler(l logger.Logger, db *gorm.DB, renderRuntime RenderRuntime) *Handler {
	return &Handler{logger: l, db: db, runtime: renderRuntime}
}
