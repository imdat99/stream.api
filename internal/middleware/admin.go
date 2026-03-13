//go:build ignore
// +build ignore

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

// RequireAdmin returns a Gin middleware that blocks non-admin users.
// Must be placed after the auth middleware so "user" is set in the context.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userValue, exists := c.Get("user")
		if !exists {
			response.Error(c, http.StatusUnauthorized, "Unauthorized")
			return
		}

		user, ok := userValue.(*model.User)
		if !ok || user == nil {
			response.Error(c, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if user.Role == nil || strings.ToUpper(*user.Role) != "ADMIN" {
			response.Error(c, http.StatusForbidden, "Admin access required")
			return
		}

		c.Next()
	}
}
