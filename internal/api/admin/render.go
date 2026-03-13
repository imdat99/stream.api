//go:build ignore
// +build ignore

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"stream.api/pkg/response"
)

type createJobRequest struct {
	Command   string            `json:"command"`
	Image     string            `json:"image"`
	Env       map[string]string `json:"env"`
	Priority  int               `json:"priority"`
	UserID    string            `json:"user_id"`
	Name      string            `json:"name"`
	TimeLimit int64             `json:"time_limit"`
}

// @Summary List render jobs
// @Description Returns paginated render jobs for admin management
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param offset query int false "Offset"
// @Param limit query int false "Limit"
// @Param agent_id query string false "Agent ID"
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /admin/jobs [get]
func (h *Handler) ListJobs(c *gin.Context) {
	offset := parseInt(c.Query("offset"), 0)
	limit := parseInt(c.Query("limit"), 20)
	if agentID := c.Query("agent_id"); agentID != "" {
		items, err := h.runtime.JobService().ListJobsByAgent(c.Request.Context(), agentID, offset, limit)
		if err != nil {
			response.Error(c, http.StatusInternalServerError, "Failed to list jobs")
			return
		}
		response.Success(c, items)
		return
	}
	items, err := h.runtime.JobService().ListJobs(c.Request.Context(), offset, limit)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to list jobs")
		return
	}
	response.Success(c, items)
}

// @Summary Get render job detail
// @Description Returns a render job by ID
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param id path string true "Job ID"
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/jobs/{id} [get]
func (h *Handler) GetJob(c *gin.Context) {
	job, err := h.runtime.JobService().GetJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusNotFound, "Job not found")
		return
	}
	response.Success(c, gin.H{"job": job})
}

// @Summary Get render job logs
// @Description Returns plain text logs for a render job
// @Tags admin-render
// @Security BearerAuth
// @Produce plain
// @Param id path string true "Job ID"
// @Success 200 {string} string
// @Failure 404 {object} response.Response
// @Router /admin/jobs/{id}/logs [get]
func (h *Handler) GetJobLogs(c *gin.Context) {
	job, err := h.runtime.JobService().GetJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusNotFound, "Job not found")
		return
	}
	c.String(http.StatusOK, job.Logs)
}

// @Summary Create render job
// @Description Queues a new render job for agents
// @Tags admin-render
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param payload body createJobRequest true "Job payload"
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /admin/jobs [post]
func (h *Handler) CreateJob(c *gin.Context) {
	var req createJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	if req.Command == "" {
		response.Error(c, http.StatusBadRequest, "Command is required")
		return
	}
	if req.Image == "" {
		req.Image = "alpine"
	}
	if req.Name == "" {
		req.Name = req.Command
	}
	payload, _ := json.Marshal(map[string]interface{}{"image": req.Image, "commands": []string{req.Command}, "environment": req.Env})
	job, err := h.runtime.JobService().CreateJob(c.Request.Context(), req.UserID, req.Name, payload, req.Priority, req.TimeLimit)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to create job")
		return
	}
	response.Created(c, gin.H{"job": job})
}

// @Summary Cancel render job
// @Description Cancels a pending or running render job
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param id path string true "Job ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /admin/jobs/{id}/cancel [post]
func (h *Handler) CancelJob(c *gin.Context) {
	if err := h.runtime.JobService().CancelJob(c.Request.Context(), c.Param("id")); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, gin.H{"status": "cancelled", "job_id": c.Param("id")})
}

// @Summary Retry render job
// @Description Retries a failed or cancelled render job
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param id path string true "Job ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /admin/jobs/{id}/retry [post]
func (h *Handler) RetryJob(c *gin.Context) {
	job, err := h.runtime.JobService().RetryJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, gin.H{"job": job})
}

// @Summary List connected render agents
// @Description Returns currently connected render agents and current runtime stats
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /admin/agents [get]
func (h *Handler) ListAgents(c *gin.Context) {
	response.Success(c, gin.H{"agents": h.runtime.AgentRuntime().ListAgentsWithStats()})
}

// @Summary Restart connected render agent
// @Description Sends a restart command to a currently connected render agent
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param id path string true "Agent ID"
// @Success 200 {object} response.Response
// @Failure 503 {object} response.Response
// @Router /admin/agents/{id}/restart [post]
func (h *Handler) RestartAgent(c *gin.Context) {
	if ok := h.runtime.AgentRuntime().SendCommand(c.Param("id"), "restart"); !ok {
		response.Error(c, http.StatusServiceUnavailable, "Agent not active or command channel full")
		return
	}
	response.Success(c, gin.H{"status": "restart command sent"})
}

// @Summary Update connected render agent
// @Description Sends an update command to a currently connected render agent
// @Tags admin-render
// @Security BearerAuth
// @Produce json
// @Param id path string true "Agent ID"
// @Success 200 {object} response.Response
// @Failure 503 {object} response.Response
// @Router /admin/agents/{id}/update [post]
func (h *Handler) UpdateAgent(c *gin.Context) {
	if ok := h.runtime.AgentRuntime().SendCommand(c.Param("id"), "update"); !ok {
		response.Error(c, http.StatusServiceUnavailable, "Agent not active or command channel full")
		return
	}
	response.Success(c, gin.H{"status": "update command sent"})
}

func parseInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	var result int
	if _, err := fmt.Sscanf(value, "%d", &result); err != nil {
		return fallback
	}
	return result
}
