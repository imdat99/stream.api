//go:build ignore
// +build ignore

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/token"
)

type AuthMiddleware struct {
	authenticator *Authenticator
}

func NewAuthMiddleware(c cache.Cache, t token.Provider, _ *config.Config, db *gorm.DB, l logger.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		authenticator: NewAuthenticator(c, t, db, l),
	}
}

func (m *AuthMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := m.authenticator.Authenticate(c.Request.Context(), AuthRequest{
			Authorization: c.GetHeader("Authorization"),
			CookieHeader:  c.GetHeader("Cookie"),
		})
		if err != nil {
			authErr, ok := err.(*AuthError)
			if !ok {
				response.Error(c, http.StatusInternalServerError, "Authentication failed")
				return
			}
			response.Error(c, authErr.StatusCode, authErr.Message)
			return
		}

		for _, cookie := range result.SetCookies {
			c.Header("Set-Cookie", cookie)
		}

		c.Set("userID", result.UserID)
		c.Set("user", result.User)
		c.Next()
	}
}
