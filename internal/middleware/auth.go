package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"stream.api/internal/config"
	"stream.api/internal/database/query"
	"stream.api/pkg/cache"
	"stream.api/pkg/response"
	"stream.api/pkg/token"
)

const (
	CookieName = "auth_token" // Backward compatibility if needed, but we use access_token now
)

type AuthMiddleware struct {
	cache cache.Cache
	token token.Provider
}

func NewAuthMiddleware(c cache.Cache, t token.Provider, cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		cache: c,
		token: t,
	}
}

func (m *AuthMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		var userID string
		var claims *token.Claims
		var err error

		// 1. Try Access Token (Header or Cookie)
		var accessToken string
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && strings.ToUpper(authHeader[0:7]) == "BEARER " {
			accessToken = authHeader[7:]
		}

		if accessToken == "" {
			cookie, err := c.Cookie("access_token")
			if err == nil {
				accessToken = cookie
			}
		}

		if accessToken != "" {
			claims, err = m.token.ParseToken(accessToken)
			if err == nil {
				userID = claims.UserID
			}
		}

		// 2. If Access Token invalid/missing, Try Refresh Token
		if userID == "" {
			refreshToken, errRefresh := c.Cookie("refresh_token")
			if errRefresh != nil {
				response.Error(c, http.StatusUnauthorized, "Unauthorized: No token")
				return
			}

			// Validate Refresh Token (JWT signature)
			// Problem regarding pkg/token parsing: Generates MapClaims but ParseToken expects Claims struct.
			// Let's rely on Redis mostly, or assume ParseToken *fails* if claims mismatch, which is fine.
			// Better: Assume we can parse at least standard claims or check Redis directly?
			// But we need the UUID inside the token to check Redis key `refresh_uuid:{uuid}`.
			// WORKAROUND: In pkg/token/jwt.go we defined `rtClaims["refresh_uuid"]`.
			// `ParseToken` attempts to map to `Claims`. It likely won't map unknown fields but `Valid` might be true if struct has RegisteredClaims?
			// Actually `jwt.ParseWithClaims` will succeed if signature matches, even if some fields are missing in struct.
			// But we need `refresh_uuid`!
			//
			// We MUST parse as MapClaims here or update pkg/token.
			// For this execution, I will parse as MapClaims locally to unblock.

			// Validate Refresh Token (JWT signature)
			// Parse using local helper to check refresh_uuid claim
			// We can use m.token.ParseMapToken which we implemented
			rtClaims, err := m.token.ParseMapToken(refreshToken)
			if err != nil {
				response.Error(c, http.StatusUnauthorized, "Unauthorized: Invalid refresh token")
				return
			}

			refreshUUID, ok := rtClaims["refresh_uuid"].(string)
			if !ok {
				response.Error(c, http.StatusUnauthorized, "Unauthorized: Invalid refresh token claim")
				return
			}

			// Check Redis
			redisKey := "refresh_uuid:" + refreshUUID
			userIDStr, err := m.cache.Get(ctx, redisKey)
			if err != nil {
				// Assuming Get returns error on miss or failure
				response.Error(c, http.StatusUnauthorized, "Unauthorized: Session expired or invalid")
				return
			}
			userID = userIDStr

			// Refresh Success: Generate NEW Pair (Rotational or just new Access?)
			// Let's just issue new Access Token. Refresh Token rotation is safer but complex (need to update Redis key).
			// We will just issue new Access Token.

			// Need User Role/Email for Access Token claims.
			u := query.User
			userObj, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
			if err != nil {
				response.Error(c, http.StatusUnauthorized, "User not found")
				return
			}

			// Calling pkg/token.GenerateTokenPair generates BOTH.
			// If we want new Access we can regenerate pair and update tokens.
			// Updating refresh token extends session (Slide expiration).

			newTd, err := m.token.GenerateTokenPair(userID, userObj.Email, userObj.Role)
			if err == nil {
				// Delete old refresh token from Redis?
				m.cache.Del(ctx, redisKey)
				// Set new
				m.cache.Set(ctx, "refresh_uuid:"+newTd.RefreshUUID, userID, time.Until(time.Unix(newTd.RtExpires, 0)))

				// Set Cookies
				c.SetCookie("access_token", newTd.AccessToken, int(newTd.AtExpires-time.Now().Unix()), "/", "", false, true)
				c.SetCookie("refresh_token", newTd.RefreshToken, int(newTd.RtExpires-time.Now().Unix()), "/", "", false, true)
			}
		}

		// 3. User Lookup / Block Check
		u := query.User
		user, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
		if err != nil {
			response.Error(c, http.StatusUnauthorized, "Unauthorized: User not found")
			return
		}

		if strings.ToLower(user.Role) == "block" {
			response.Error(c, http.StatusForbidden, "Forbidden: User is blocked")
			return
		}

		c.Set("userID", user.ID)
		c.Set("user", user)
		c.Next()
	}
}

// Helper to parse generic claims
// Removed parseMapToken as it is now in TokenProvider interface
