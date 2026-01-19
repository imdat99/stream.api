package plan

import "github.com/gin-gonic/gin"

// PlanHandler defines the interface for plan operations
type PlanHandler interface {
	ListPlans(c *gin.Context)
}
