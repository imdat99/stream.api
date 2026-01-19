package app

import (
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/internal/api/auth"
	"stream.api/internal/api/payment"
	"stream.api/internal/api/plan"
	"stream.api/internal/api/video"
	"stream.api/internal/config"
	"stream.api/internal/middleware"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "stream.api/docs"
)

func SetupRouter(cfg *config.Config, db *gorm.DB, c cache.Cache, t token.Provider, l logger.Logger) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Global Middleware
	r.Use(gin.Logger())
	r.Use(middleware.Recovery())     // Custom Recovery with JSON response
	r.Use(middleware.ErrorHandler()) // Handle c.Errors
	// CORS Middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:8080"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))
	// Only enable Swagger in non-release mode
	if cfg.Server.Mode != "release" {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Global Middleware (Logger, Recovery are default)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "up",
		})
	})

	// Auth Handler
	authHandler := auth.NewHandler(c, t, l, cfg)
	// api := r.Group("/v")
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/forgot-password", authHandler.ForgotPassword)
		authGroup.POST("/reset-password", authHandler.ResetPassword)
		authGroup.GET("/google/login", authHandler.LoginGoogle)
		authGroup.GET("/google/callback", authHandler.GoogleCallback)
	}

	// Auth Middleware
	authMiddleware := middleware.NewAuthMiddleware(c, t, cfg)

	// Init Storage Provider (S3)
	s3Provider, err := storage.NewS3Provider(cfg)
	if err != nil {
		l.Error("Failed to initialize S3 provider", "error", err)
		// We might want to panic or continue with warning depending on criticality.
		// For now, let's log and proceed, but video uploads will fail.
	}

	// Handlers
	planHandler := plan.NewHandler(l, cfg)
	paymentHandler := payment.NewHandler(l, cfg)
	videoHandler := video.NewHandler(l, cfg, s3Provider)

	// Example protected group
	protected := r.Group("")
	protected.Use(authMiddleware.Handle())
	{
		protected.GET("/me", func(c *gin.Context) {
			user, _ := c.Get("user")
			response.Success(c, gin.H{"user": user})
			// c.JSON(http.StatusOK, gin.H{
			// 	"user": user,
			// })
		})
		protected.POST("/auth/logout", authHandler.Logout)

		// Plans
		plans := protected.Group("/plans")
		plans.GET("", planHandler.ListPlans)

		// Payments
		payments := protected.Group("/payments")
		payments.POST("", paymentHandler.CreatePayment)

		// Videos
		video := protected.Group("/videos")
		video.POST("/upload-url", videoHandler.GetUploadURL)
		video.POST("", videoHandler.CreateVideo)
		video.GET("", videoHandler.ListVideos)
		video.GET("/:id", videoHandler.GetVideo)
	}

	return r
}
