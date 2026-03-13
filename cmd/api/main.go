package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"stream.api/internal/config"
	"stream.api/internal/database/query"
	videoruntime "stream.api/internal/video/runtime"
	"stream.api/pkg/cache"
	"stream.api/pkg/database"
	"stream.api/pkg/logger"
	"stream.api/pkg/token"
)

func main() {
	// 1. Load Config
	cfg, err := config.LoadConfig()
	if err != nil {
		// Use default if env/file issues, usually LoadConfig returns error only on serious issues
		// But here if it returns error we might want to panic
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Connect DB
	db, err := database.Connect(cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	// Initialize generated query
	query.SetDefault(db)

	// TODO: Tách database migration ra luồng riêng nếu cần.

	// 3. Connect Redis (Cache Interface)
	rdb, err := cache.NewRedisCache(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatalf("Failed to connect to redis: %v", err)
	}
	defer rdb.Close() // Ensure we close cache on exit

	// 4. Initialize Components
	tokenProvider := token.NewJWTProvider(cfg.JWT.Secret)
	appLogger := logger.NewLogger(cfg.Server.Mode)

	module, err := videoruntime.NewModule(context.Background(), cfg, db, rdb, tokenProvider, appLogger)
	if err != nil {
		log.Fatalf("Failed to setup gRPC runtime module: %v", err)
	}

	grpcListener, err := net.Listen("tcp", ":"+cfg.Server.GRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port %s: %v", cfg.Server.GRPCPort, err)
	}

	go func() {
		log.Printf("Starting gRPC server on port %s", cfg.Server.GRPCPort)
		if err := module.ServeGRPC(grpcListener); err != nil {
			log.Fatalf("Failed to run gRPC server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down gRPC server...")

	module.Shutdown()
	_ = grpcListener.Close()

	log.Println("Server exiting")
}
