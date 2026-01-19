package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stream.api/internal/app"
	"stream.api/internal/config"
	"stream.api/internal/database/query"
	"stream.api/pkg/cache"
	"stream.api/pkg/database"
	"stream.api/pkg/logger"
	"stream.api/pkg/token"
)

// @title           Stream API
// @version         1.0
// @description     This is the API server for Stream application.
// @termsOfService  http://swagger.io/terms/

// @contact.name    API Support
// @contact.url     http://www.swagger.io/support
// @contact.email   support@swagger.io

// @license.name    Apache 2.0
// @license.url     http://www.apache.org/licenses/LICENSE-2.0.html

// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
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

	// 3. Connect Redis (Cache Interface)
	rdb, err := cache.NewRedisCache(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatalf("Failed to connect to redis: %v", err)
	}
	defer rdb.Close() // Ensure we close cache on exit

	// 4. Initialize Components
	tokenProvider := token.NewJWTProvider(cfg.JWT.Secret)
	appLogger := logger.NewLogger(cfg.Server.Mode)

	// 5. Setup Router
	r := app.SetupRouter(cfg, db, rdb, tokenProvider, appLogger)

	// 5. Run Server with Graceful Shutdown
	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: r,
	}

	go func() {
		log.Printf("Starting server on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to run server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Println("Server exiting")
}
