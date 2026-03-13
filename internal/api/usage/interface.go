//go:build ignore
// +build ignore

package usage

import "github.com/gin-gonic/gin"

// UsageHandler defines the interface for usage operations
type UsageHandler interface {
	GetUsage(c *gin.Context)
}
