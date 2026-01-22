package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/token"
)

type handler struct {
	cache       cache.Cache
	token       token.Provider
	logger      logger.Logger
	googleOauth *oauth2.Config
}

// NewHandler creates a new instance of Handler
func NewHandler(c cache.Cache, t token.Provider, l logger.Logger, cfg *config.Config) AuthHandler {
	return &handler{
		cache:  c,
		token:  t,
		logger: l,
		googleOauth: &oauth2.Config{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			RedirectURL:  cfg.Google.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (h *handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.Email.Eq(req.Email)).First()
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password (if user has password, google users might not)
	if user.Password == nil || *user.Password == "" {
		response.Error(c, http.StatusUnauthorized, "Please login with Google")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(req.Password)); err != nil {
		response.Error(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	h.generateAndSetTokens(c, user.ID, user.Email, *user.Role)
	response.Success(c, gin.H{"user": user})
}

func (h *handler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		claims, err := h.token.ParseMapToken(refreshToken)
		if err == nil {
			if refreshUUID, ok := claims["refresh_uuid"].(string); ok {
				h.cache.Del(c.Request.Context(), "refresh_uuid:"+refreshUUID)
			}
		}
	}

	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	response.Success(c, "Logged out")
}

func (h *handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	u := query.User
	// Check existing
	count, _ := u.WithContext(c.Request.Context()).Where(u.Email.Eq(req.Email)).Count()
	if count > 0 {
		response.Error(c, http.StatusBadRequest, "Email already registered")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.Fail(c, "Failed to hash password")
		return
	}

	password := string(hashedPassword)
	role := "USER"
	newUser := &model.User{
		ID:       uuid.New().String(),
		Email:    req.Email,
		Password: &password,
		Username: &req.Username,
		Role:     &role,
	}

	if err := u.WithContext(c.Request.Context()).Create(newUser); err != nil {
		response.Fail(c, "Failed to create user")
		return
	}

	response.Created(c, "User registered")
}

func (h *handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.Email.Eq(req.Email)).First()
	if err != nil {
		// Do not reveal
		response.Success(c, "If email exists, a reset link has been sent")
		return
	}

	tokenID := uuid.New().String()
	err = h.cache.Set(c.Request.Context(), "reset_pw:"+tokenID, user.ID, 15*time.Minute)
	if err != nil {
		h.logger.Error("Failed to set reset token", "error", err)
		response.Fail(c, "Try again later")
		return
	}

	// log.Printf replaced with logger
	h.logger.Info("Sending Password Reset Email", "email", req.Email, "token", tokenID)
	response.Success(c, gin.H{"message": "If email exists, a reset link has been sent", "debug_token": tokenID})
}

func (h *handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.cache.Get(c.Request.Context(), "reset_pw:"+req.Token)
	if err != nil {
		// Cache interface should likely separate "Not Found" vs "Error" or return error compatible with checking
		// If implementation returns redis.Nil equivalent.
		// Our Cache interface Get returns (string, error).
		// Redis implementation returns redis.Nil which is an error.
		// We'll need to check if generic cache supports "not found" check.
		// For now, simple error check.
		response.Error(c, http.StatusBadRequest, "Invalid or expired token")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		response.Fail(c, "Internal Error")
		return
	}

	u := query.User
	_, err = u.WithContext(c.Request.Context()).Where(u.ID.Eq(userID)).Update(u.Password, string(hashedPassword))
	if err != nil {
		response.Fail(c, "Failed to update password")
		return
	}

	h.cache.Del(c.Request.Context(), "reset_pw:"+req.Token)
	response.Success(c, "Password reset successfully")
}

func (h *handler) LoginGoogle(c *gin.Context) {
	url := h.googleOauth.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *handler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	tokenResp, err := h.googleOauth.Exchange(c.Request.Context(), code)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Failed to exchange token")
		return
	}

	client := h.googleOauth.Client(c.Request.Context(), tokenResp)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil || resp.StatusCode != http.StatusOK {
		response.Fail(c, "Failed to get user info")
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		response.Fail(c, "Failed to parse user info")
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.Email.Eq(googleUser.Email)).First()
	if err != nil {
		role := "USER"
		user = &model.User{
			ID:       uuid.New().String(),
			Email:    googleUser.Email,
			Username: &googleUser.Name,
			GoogleID: &googleUser.ID,
			Avatar:   &googleUser.Picture,
			Role:     &role,
		}
		if err := u.WithContext(c.Request.Context()).Create(user); err != nil {
			response.Fail(c, "Failed to create user")
			return
		}
	} else if user.GoogleID == nil || *user.GoogleID == "" {
		u.WithContext(c.Request.Context()).Where(u.ID.Eq(user.ID)).Update(u.GoogleID, googleUser.ID)
	}

	h.generateAndSetTokens(c, user.ID, user.Email, *user.Role)
	response.Success(c, gin.H{"user": user})
}

func (h *handler) generateAndSetTokens(c *gin.Context, userID, email, role string) {
	td, err := h.token.GenerateTokenPair(userID, email, role)
	if err != nil {
		h.logger.Error("Token generation failed", "error", err)
		response.Fail(c, "Error generating tokens")
		return
	}

	// Store Refresh UUID in Redis
	err = h.cache.Set(c.Request.Context(), "refresh_uuid:"+td.RefreshUUID, userID, time.Until(time.Unix(td.RtExpires, 0)))
	if err != nil {
		h.logger.Error("Session storage failed", "error", err)
		response.Fail(c, "Error storing session")
		return
	}

	c.SetCookie("access_token", td.AccessToken, int(td.AtExpires-time.Now().Unix()), "/", "", false, true)
	c.SetCookie("refresh_token", td.RefreshToken, int(td.RtExpires-time.Now().Unix()), "/", "", false, true)
}
