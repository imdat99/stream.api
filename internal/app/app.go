//go:build ignore
// +build ignore

package app

import (
	"context"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/internal/api/admin"
	"stream.api/internal/api/adtemplates"
	"stream.api/internal/api/auth"
	"stream.api/internal/api/domains"
	"stream.api/internal/api/notifications"
	"stream.api/internal/api/payment"
	"stream.api/internal/api/plan"
	"stream.api/internal/api/preferences"
	"stream.api/internal/api/usage"
	"stream.api/internal/api/video"
	"stream.api/internal/config"
	"stream.api/internal/middleware"
	videoruntime "stream.api/internal/video/runtime"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(cfg *config.Config, db *gorm.DB, c cache.Cache, t token.Provider, l logger.Logger) (*gin.Engine, *videoruntime.Module, error) {
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
		AllowOrigins:     cfg.CORS.AllowOrigins,
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
	authHandler := auth.NewHandler(c, t, l, cfg, db)
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
	authMiddleware := middleware.NewAuthMiddleware(c, t, cfg, db, l)

	// Init Storage Provider (S3)
	s3Provider, err := storage.NewS3Provider(cfg)
	if err != nil {
		l.Error("Failed to initialize S3 provider", "error", err)
		// We might want to panic or continue with warning depending on criticality.
		// For now, let's log and proceed, but video uploads will fail.
	}

	// Handlers
	planHandler := plan.NewHandler(l, cfg, db)
	paymentHandler := payment.NewHandler(l, cfg, db)
	usageHandler := usage.NewHandler(l, db)
	videoHandler := video.NewHandler(l, cfg, db, s3Provider)
	preferencesHandler := preferences.NewHandler(l, db)
	notificationHandler := notifications.NewHandler(l, db)
	domainHandler := domains.NewHandler(l, db)
	adTemplateHandler := adtemplates.NewHandler(l, db)

	// Example protected group
	protected := r.Group("")
	protected.Use(authMiddleware.Handle())
	{
		protected.GET("/me", authHandler.GetMe)
		protected.PUT("/me", authHandler.UpdateMe)
		protected.DELETE("/me", authHandler.DeleteMe)
		protected.POST("/me/clear-data", authHandler.ClearMyData)
		protected.POST("/auth/logout", authHandler.Logout)
		protected.POST("/auth/change-password", authHandler.ChangePassword)

		preferences := protected.Group("/settings/preferences")
		preferences.GET("", preferencesHandler.GetPreferences)
		preferences.PUT("", preferencesHandler.UpdatePreferences)

		notifications := protected.Group("/notifications")
		notifications.GET("", notificationHandler.ListNotifications)
		notifications.POST("/:id/read", notificationHandler.MarkRead)
		notifications.POST("/read-all", notificationHandler.MarkAllRead)
		notifications.DELETE("/:id", notificationHandler.DeleteNotification)
		notifications.DELETE("", notificationHandler.ClearNotifications)

		domains := protected.Group("/domains")
		domains.GET("", domainHandler.ListDomains)
		domains.POST("", domainHandler.CreateDomain)
		domains.DELETE("/:id", domainHandler.DeleteDomain)

		adTemplates := protected.Group("/ad-templates")
		adTemplates.GET("", adTemplateHandler.ListTemplates)
		adTemplates.POST("", adTemplateHandler.CreateTemplate)
		adTemplates.PUT("/:id", adTemplateHandler.UpdateTemplate)
		adTemplates.DELETE("/:id", adTemplateHandler.DeleteTemplate)

		// Plans
		plans := protected.Group("/plans")
		plans.GET("", planHandler.ListPlans)

		// Payments
		payments := protected.Group("/payments")
		payments.POST("", paymentHandler.CreatePayment)
		payments.GET("/history", paymentHandler.ListPaymentHistory)
		payments.GET("/:id/invoice", paymentHandler.DownloadInvoice)
		wallet := protected.Group("/wallet")
		wallet.POST("/topups", paymentHandler.TopupWallet)

		protected.GET("/usage", usageHandler.GetUsage)

		// Videos
		video := protected.Group("/videos")
		video.POST("/upload-url", videoHandler.GetUploadURL)
		video.POST("", videoHandler.CreateVideo)
		video.GET("", videoHandler.ListVideos)
		video.GET("/:id", videoHandler.GetVideo)
		video.PUT("/:id", videoHandler.UpdateVideo)
		video.DELETE("/:id", videoHandler.DeleteVideo)
	}

	renderModule, err := videoruntime.NewModule(context.Background(), cfg, db, c, t, l)
	if err != nil {
		return nil, nil, err
	}

	r.Use(videoruntime.MetricsMiddleware())
	r.GET("/health/live", renderModule.HandleLive)
	r.GET("/health/ready", renderModule.HandleReady)
	r.GET("/health/detailed", renderModule.HandleDetailed)
	r.GET("/metrics", renderModule.MetricsHandler())

	// Admin routes — require auth + admin role
	adminHandler := admin.NewHandler(l, db, renderModule)
	adminGroup := r.Group("/admin")
	adminGroup.Use(authMiddleware.Handle())
	adminGroup.Use(middleware.RequireAdmin())
	{
		adminGroup.GET("/dashboard", adminHandler.Dashboard)

		adminGroup.GET("/users", adminHandler.ListUsers)
		adminGroup.POST("/users", adminHandler.CreateUser)
		adminGroup.GET("/users/:id", adminHandler.GetUser)
		adminGroup.PUT("/users/:id", adminHandler.UpdateUser)
		adminGroup.PUT("/users/:id/role", adminHandler.UpdateUserRole)
		adminGroup.DELETE("/users/:id", adminHandler.DeleteUser)

		adminGroup.GET("/videos", adminHandler.ListVideos)
		adminGroup.POST("/videos", adminHandler.CreateVideo)
		adminGroup.GET("/videos/:id", adminHandler.GetVideo)
		adminGroup.PUT("/videos/:id", adminHandler.UpdateVideo)
		adminGroup.DELETE("/videos/:id", adminHandler.DeleteVideo)

		adminGroup.GET("/payments", adminHandler.ListPayments)
		adminGroup.POST("/payments", adminHandler.CreatePayment)
		adminGroup.GET("/payments/:id", adminHandler.GetPayment)
		adminGroup.PUT("/payments/:id", adminHandler.UpdatePayment)

		adminGroup.GET("/plans", adminHandler.ListPlans)
		adminGroup.POST("/plans", adminHandler.CreatePlan)
		adminGroup.PUT("/plans/:id", adminHandler.UpdatePlan)
		adminGroup.DELETE("/plans/:id", adminHandler.DeletePlan)

		adminGroup.GET("/ad-templates", adminHandler.ListAdTemplates)
		adminGroup.POST("/ad-templates", adminHandler.CreateAdTemplate)
		adminGroup.GET("/ad-templates/:id", adminHandler.GetAdTemplate)
		adminGroup.PUT("/ad-templates/:id", adminHandler.UpdateAdTemplate)
		adminGroup.DELETE("/ad-templates/:id", adminHandler.DeleteAdTemplate)

		adminGroup.GET("/jobs", adminHandler.ListJobs)
		adminGroup.POST("/jobs", adminHandler.CreateJob)
		adminGroup.GET("/jobs/:id", adminHandler.GetJob)
		adminGroup.GET("/jobs/:id/logs", adminHandler.GetJobLogs)
		adminGroup.POST("/jobs/:id/cancel", adminHandler.CancelJob)
		adminGroup.POST("/jobs/:id/retry", adminHandler.RetryJob)
		adminGroup.GET("/agents", adminHandler.ListAgents)
		adminGroup.POST("/agents/:id/restart", adminHandler.RestartAgent)
		adminGroup.POST("/agents/:id/update", adminHandler.UpdateAgent)
	}

	return r, renderModule, nil
}
