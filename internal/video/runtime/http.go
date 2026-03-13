//go:build ignore
// +build ignore

package runtime

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (m *Module) MetricsHandler() gin.HandlerFunc {
	return gin.WrapH(promhttp.Handler())
}

// HandleLive godoc
// @Summary Liveness health check
// @Description Returns liveness status for the API and render module
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /health/live [get]
func (m *Module) HandleLive(c *gin.Context) {
	status, code := m.healthService.SimpleHealthCheck(c.Request.Context())
	c.JSON(code, gin.H{"status": status})
}

// HandleReady godoc
// @Summary Readiness health check
// @Description Returns readiness status including render gRPC availability flag
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 503 {object} map[string]interface{}
// @Router /health/ready [get]
func (m *Module) HandleReady(c *gin.Context) {
	status, code := m.healthService.SimpleHealthCheck(c.Request.Context())
	c.JSON(code, gin.H{"status": status, "grpc_enabled": m.grpcServer != nil})
}

// HandleDetailed godoc
// @Summary Detailed health check
// @Description Returns detailed health state for database, redis, and render dependencies
// @Tags health
// @Produce json
// @Success 200 {object} services.HealthReport
// @Router /health/detailed [get]
func (m *Module) HandleDetailed(c *gin.Context) {
	c.JSON(http.StatusOK, m.healthService.CheckHealth(c.Request.Context()))
}

var (
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "stream_api_http_requests_total", Help: "Total HTTP requests."}, []string{"method", "path", "status"})
	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "stream_api_http_request_duration_seconds", Help: "HTTP request duration."}, []string{"method", "path"})
)

func init() {
	prometheus.MustRegister(httpRequests, httpDuration)
}

func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		httpRequests.WithLabelValues(c.Request.Method, path, http.StatusText(c.Writer.Status())).Inc()
		httpDuration.WithLabelValues(c.Request.Method, path).Observe(time.Since(start).Seconds())
	}
}
