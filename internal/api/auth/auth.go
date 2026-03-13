//go:build ignore
// +build ignore

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/response"
	"stream.api/pkg/token"
)

type handler struct {
	cache              cache.Cache
	token              token.Provider
	logger             logger.Logger
	db                 *gorm.DB
	googleOauth        *oauth2.Config
	googleStateTTL     time.Duration
	frontendBaseURL    string
	googleFinalizePath string
}

// NewHandler creates a new instance of Handler
func NewHandler(c cache.Cache, t token.Provider, l logger.Logger, cfg *config.Config, db *gorm.DB) AuthHandler {
	stateTTL := time.Duration(cfg.Google.StateTTLMinute) * time.Minute
	if stateTTL <= 0 {
		stateTTL = 10 * time.Minute
	}

	return &handler{
		cache:              c,
		token:              t,
		logger:             l,
		db:                 db,
		googleStateTTL:     stateTTL,
		frontendBaseURL:    strings.TrimRight(cfg.Frontend.BaseURL, "/"),
		googleFinalizePath: cfg.Frontend.GoogleAuthFinalizePath,
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

// @Summary      Login
// @Description  Login with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      LoginRequest  true  "Login payload"
// @Success      200      {object}  response.Response{data=UserPayload}
// @Failure      400      {object}  response.Response
// @Failure      401      {object}  response.Response
// @Router       /auth/login [post]
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

	if err := h.generateAndSetTokens(c, user.ID, user.Email, safeRole(user.Role)); err != nil {
		return
	}
	h.respondWithUserPayload(c, user)
}

// @Summary      Logout
// @Description  Logout user and clear cookies
// @Tags         auth
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Router       /auth/logout [post]
// @Security     BearerAuth
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

// @Summary      Register
// @Description  Register a new user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterRequest  true  "Registration payload"
// @Success      201      {object}  response.Response
// @Failure      400      {object}  response.Response
// @Failure      500      {object}  response.Response
// @Router       /auth/register [post]
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

// @Summary      Forgot Password
// @Description  Request password reset link
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      ForgotPasswordRequest  true  "Forgot password payload"
// @Success      200      {object}  response.Response
// @Failure      400      {object}  response.Response
// @Failure      500      {object}  response.Response
// @Router       /auth/forgot-password [post]
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

// @Summary      Reset Password
// @Description  Reset password using token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      ResetPasswordRequest  true  "Reset password payload"
// @Success      200      {object}  response.Response
// @Failure      400      {object}  response.Response
// @Failure      500      {object}  response.Response
// @Router       /auth/reset-password [post]
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

// @Summary      Google Login
// @Description  Redirect to Google for Login
// @Tags         auth
// @Router       /auth/google/login [get]
func (h *handler) LoginGoogle(c *gin.Context) {
	state, err := generateOAuthState()
	if err != nil {
		h.logger.Error("Failed to generate Google OAuth state", "error", err)
		response.Fail(c, "Failed to start Google login")
		return
	}

	if err := h.cache.Set(c.Request.Context(), googleOAuthStateCacheKey(state), "1", h.googleStateTTL); err != nil {
		h.logger.Error("Failed to persist Google OAuth state", "error", err)
		response.Fail(c, "Failed to start Google login")
		return
	}

	url := h.googleOauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// @Summary      Google Callback
// @Description  Callback for Google Login
// @Tags         auth
// @Success      307
// @Failure      400  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /auth/google/callback [get]
func (h *handler) GoogleCallback(c *gin.Context) {
	if oauthError := strings.TrimSpace(c.Query("error")); oauthError != "" {
		h.redirectToGoogleFinalize(c, "error", oauthError)
		return
	}

	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		h.redirectToGoogleFinalize(c, "error", "missing_state")
		return
	}

	cachedState, err := h.cache.Get(c.Request.Context(), googleOAuthStateCacheKey(state))
	if err != nil || cachedState == "" {
		h.redirectToGoogleFinalize(c, "error", "invalid_state")
		return
	}
	_ = h.cache.Del(c.Request.Context(), googleOAuthStateCacheKey(state))

	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		h.redirectToGoogleFinalize(c, "error", "missing_code")
		return
	}

	tokenResp, err := h.googleOauth.Exchange(c.Request.Context(), code)
	if err != nil {
		h.logger.Error("Failed to exchange Google OAuth token", "error", err)
		h.redirectToGoogleFinalize(c, "error", "exchange_failed")
		return
	}

	client := h.googleOauth.Client(c.Request.Context(), tokenResp)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		h.logger.Error("Failed to fetch Google user info", "error", err)
		h.redirectToGoogleFinalize(c, "error", "userinfo_failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.logger.Error("Google user info returned non-200", "status", resp.StatusCode)
		h.redirectToGoogleFinalize(c, "error", "userinfo_failed")
		return
	}

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		h.logger.Error("Failed to decode Google user info", "error", err)
		h.redirectToGoogleFinalize(c, "error", "userinfo_parse_failed")
		return
	}

	if strings.TrimSpace(googleUser.Email) == "" {
		h.redirectToGoogleFinalize(c, "error", "missing_email")
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.Email.Eq(googleUser.Email)).First()
	if err != nil {
		role := "USER"
		user = &model.User{
			ID:       uuid.New().String(),
			Email:    googleUser.Email,
			Username: stringPointerOrNil(googleUser.Name),
			GoogleID: stringPointerOrNil(googleUser.ID),
			Avatar:   stringPointerOrNil(googleUser.Picture),
			Role:     &role,
		}
		if err := u.WithContext(c.Request.Context()).Create(user); err != nil {
			h.logger.Error("Failed to create Google user", "error", err)
			h.redirectToGoogleFinalize(c, "error", "create_user_failed")
			return
		}
	} else {
		updates := map[string]interface{}{}
		if user.GoogleID == nil || strings.TrimSpace(*user.GoogleID) == "" {
			updates["google_id"] = googleUser.ID
		}
		if user.Avatar == nil || strings.TrimSpace(*user.Avatar) == "" {
			updates["avatar"] = googleUser.Picture
		}
		if user.Username == nil || strings.TrimSpace(*user.Username) == "" {
			updates["username"] = googleUser.Name
		}
		if len(updates) > 0 {
			if err := h.db.WithContext(c.Request.Context()).Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
				h.logger.Error("Failed to update Google user", "error", err)
				h.redirectToGoogleFinalize(c, "error", "update_user_failed")
				return
			}
			user, err = u.WithContext(c.Request.Context()).Where(u.ID.Eq(user.ID)).First()
			if err != nil {
				h.logger.Error("Failed to reload Google user", "error", err)
				h.redirectToGoogleFinalize(c, "error", "reload_user_failed")
				return
			}
		}
	}

	if err := h.generateAndSetTokens(c, user.ID, user.Email, safeRole(user.Role)); err != nil {
		h.redirectToGoogleFinalize(c, "error", "session_failed")
		return
	}

	if h.frontendBaseURL == "" {
		h.respondWithUserPayload(c, user)
		return
	}

	h.redirectToGoogleFinalize(c, "success", "")
}

// @Summary      Get Current User
// @Description  Get the authenticated user's profile payload
// @Tags         auth
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Router       /me [get]
// @Security     BearerAuth
func (h *handler) GetMe(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.ID.Eq(userID)).First()
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	h.respondWithUserPayload(c, user)
}

// @Summary      Update Current User
// @Description  Update the authenticated user's profile information
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body UpdateMeRequest true "Profile payload"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /me [put]
// @Security     BearerAuth
func (h *handler) UpdateMe(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req UpdateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := UpdateUserProfile(c.Request.Context(), h.db, h.logger, userID, UpdateProfileInput{
		Username: req.Username,
		Email:    req.Email,
		Language: req.Language,
		Locale:   req.Locale,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrEmailRequired):
			response.Error(c, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrEmailAlreadyRegistered):
			response.Error(c, http.StatusBadRequest, err.Error())
		default:
			response.Fail(c, "Failed to update profile")
		}
		return
	}

	h.respondWithUserPayload(c, user)
}

// @Summary      Change Password
// @Description  Change the authenticated user's local password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ChangePasswordRequest true "Password payload"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /auth/change-password [post]
// @Security     BearerAuth
func (h *handler) ChangePassword(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	u := query.User
	user, err := u.WithContext(c.Request.Context()).Where(u.ID.Eq(userID)).First()
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if user.Password == nil || strings.TrimSpace(*user.Password) == "" {
		response.Error(c, http.StatusBadRequest, "This account does not have a local password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(req.CurrentPassword)); err != nil {
		response.Error(c, http.StatusBadRequest, "Current password is incorrect")
		return
	}

	if req.CurrentPassword == req.NewPassword {
		response.Error(c, http.StatusBadRequest, "New password must be different")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		response.Fail(c, "Failed to hash password")
		return
	}

	if _, err := u.WithContext(c.Request.Context()).Where(u.ID.Eq(userID)).Update(u.Password, string(hashedPassword)); err != nil {
		h.logger.Error("Failed to change password", "error", err)
		response.Fail(c, "Failed to change password")
		return
	}

	response.Success(c, gin.H{"message": "Password changed successfully"})
}

// @Summary      Clear My Data
// @Description  Remove videos and settings-related resources for the authenticated user
// @Tags         auth
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /me/clear-data [post]
// @Security     BearerAuth
func (h *handler) ClearMyData(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	ctx := c.Request.Context()
	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{"storage_used": 0}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.logger.Error("Failed to clear user data", "error", err)
		response.Fail(c, "Failed to clear data")
		return
	}

	response.Success(c, gin.H{"message": "Data cleared successfully"})
}

// @Summary      Delete My Account
// @Description  Permanently delete the authenticated user's account and related data
// @Tags         auth
// @Produce      json
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      500  {object}  response.Response
// @Router       /me [delete]
// @Security     BearerAuth
func (h *handler) DeleteMe(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		response.Error(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	ctx := c.Request.Context()
	if err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.WalletTransaction{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.PlanSubscription{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.UserPreference{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Payment{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", userID).Delete(&model.User{}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.logger.Error("Failed to delete user", "error", err)
		response.Fail(c, "Failed to delete account")
		return
	}

	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	response.Success(c, gin.H{"message": "Account deleted successfully"})
}

func (h *handler) generateAndSetTokens(c *gin.Context, userID, email, role string) error {
	td, err := h.token.GenerateTokenPair(userID, email, role)
	if err != nil {
		h.logger.Error("Token generation failed", "error", err)
		response.Fail(c, "Error generating tokens")
		return err
	}

	// Store Refresh UUID in Redis
	err = h.cache.Set(c.Request.Context(), "refresh_uuid:"+td.RefreshUUID, userID, time.Until(time.Unix(td.RtExpires, 0)))
	if err != nil {
		h.logger.Error("Session storage failed", "error", err)
		response.Fail(c, "Error storing session")
		return err
	}

	c.SetCookie("access_token", td.AccessToken, int(td.AtExpires-time.Now().Unix()), "/", "", false, true)
	c.SetCookie("refresh_token", td.RefreshToken, int(td.RtExpires-time.Now().Unix()), "/", "", false, true)
	return nil
}

func (h *handler) respondWithUserPayload(c *gin.Context, user *model.User) {
	payload, err := BuildUserPayload(c.Request.Context(), h.db, user)
	if err != nil {
		h.logger.Error("Failed to build user payload", "error", err)
		response.Fail(c, "Failed to build user payload")
		return
	}

	response.Success(c, gin.H{"user": payload})
}

func safeRole(role *string) string {
	if role == nil || strings.TrimSpace(*role) == "" {
		return "USER"
	}
	return *role
}

func generateOAuthState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func googleOAuthStateCacheKey(state string) string {
	return "google_oauth_state:" + state
}

func stringPointerOrNil(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func (h *handler) redirectToGoogleFinalize(c *gin.Context, status, reason string) {
	finalizeURL := h.googleFinalizeURL(status, reason)
	if finalizeURL == "" {
		response.Error(c, http.StatusBadRequest, reason)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, finalizeURL)
}

func (h *handler) googleFinalizeURL(status, reason string) string {
	if h.frontendBaseURL == "" {
		return ""
	}

	finalizePath := h.googleFinalizePath
	if strings.TrimSpace(finalizePath) == "" {
		finalizePath = "/auth/google/finalize"
	}
	if !strings.HasPrefix(finalizePath, "/") {
		finalizePath = "/" + finalizePath
	}

	values := url.Values{}
	values.Set("status", status)
	if strings.TrimSpace(reason) != "" {
		values.Set("reason", reason)
	}

	return fmt.Sprintf("%s%s?%s", h.frontendBaseURL, finalizePath, values.Encode())
}
