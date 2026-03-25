package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
)

func (s *appServices) Login(ctx context.Context, req *appv1.LoginRequest) (*appv1.LoginResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	password := req.GetPassword()
	if email == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "Email and password are required")
	}

	u := query.User
	user, err := u.WithContext(ctx).Where(u.Email.Eq(email)).First()
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
	}
	if user.Password == nil || strings.TrimSpace(*user.Password) == "" {
		return nil, status.Error(codes.Unauthenticated, "Please login with Google")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
	}

	payload, err := buildUserPayload(ctx, s.db, user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.LoginResponse{User: toProtoUser(payload)}, nil
}
func (s *appServices) Register(ctx context.Context, req *appv1.RegisterRequest) (*appv1.RegisterResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	username := strings.TrimSpace(req.GetUsername())
	password := req.GetPassword()
	refUsername := strings.TrimSpace(req.GetRefUsername())
	if email == "" || username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "Username, email and password are required")
	}

	u := query.User
	count, err := u.WithContext(ctx).Where(u.Email.Eq(email)).Count()
	if err != nil {
		s.logger.Error("Failed to check existing user", "error", err)
		return nil, status.Error(codes.Internal, "Failed to register")
	}
	if count > 0 {
		return nil, status.Error(codes.InvalidArgument, "Email already registered")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to register")
	}

	referrerID, err := s.resolveSignupReferrerID(ctx, refUsername, username)
	if err != nil {
		s.logger.Error("Failed to resolve signup referrer", "error", err)
		return nil, status.Error(codes.Internal, "Failed to register")
	}

	role := "USER"
	passwordHash := string(hashedPassword)
	newUser := &model.User{
		ID:               uuid.New().String(),
		Email:            email,
		Password:         &passwordHash,
		Username:         &username,
		Role:             &role,
		ReferredByUserID: referrerID,
		ReferralEligible: model.BoolPtr(true),
	}
	if err := u.WithContext(ctx).Create(newUser); err != nil {
		s.logger.Error("Failed to create user", "error", err)
		return nil, status.Error(codes.Internal, "Failed to register")
	}

	payload, err := buildUserPayload(ctx, s.db, newUser)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.RegisterResponse{User: toProtoUser(payload)}, nil
}
func (s *appServices) Logout(ctx context.Context, _ *appv1.LogoutRequest) (*appv1.MessageResponse, error) {
	return messageResponse("Logged out"), nil
}
func (s *appServices) ChangePassword(ctx context.Context, req *appv1.ChangePasswordRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	currentPassword := req.GetCurrentPassword()
	newPassword := req.GetNewPassword()
	if currentPassword == "" || newPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "Current password and new password are required")
	}
	if currentPassword == newPassword {
		return nil, status.Error(codes.InvalidArgument, "New password must be different")
	}
	if result.User.Password == nil || strings.TrimSpace(*result.User.Password) == "" {
		return nil, status.Error(codes.InvalidArgument, "This account does not have a local password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*result.User.Password), []byte(currentPassword)); err != nil {
		return nil, status.Error(codes.InvalidArgument, "Current password is incorrect")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to change password")
	}
	if _, err := query.User.WithContext(ctx).
		Where(query.User.ID.Eq(result.UserID)).
		Update(query.User.Password, string(newHash)); err != nil {
		s.logger.Error("Failed to change password", "error", err)
		return nil, status.Error(codes.Internal, "Failed to change password")
	}
	return messageResponse("Password changed successfully"), nil
}
func (s *appServices) ForgotPassword(ctx context.Context, req *appv1.ForgotPasswordRequest) (*appv1.MessageResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "Email is required")
	}

	u := query.User
	user, err := u.WithContext(ctx).Where(u.Email.Eq(email)).First()
	if err != nil {
		return messageResponse("If email exists, a reset link has been sent"), nil
	}

	tokenID := uuid.New().String()
	if err := s.cache.Set(ctx, "reset_pw:"+tokenID, user.ID, 15*time.Minute); err != nil {
		s.logger.Error("Failed to set reset token", "error", err)
		return nil, status.Error(codes.Internal, "Try again later")
	}

	s.logger.Info("Generated password reset token", "email", email, "token", tokenID)
	return messageResponse("If email exists, a reset link has been sent"), nil
}
func (s *appServices) ResetPassword(ctx context.Context, req *appv1.ResetPasswordRequest) (*appv1.MessageResponse, error) {
	resetToken := strings.TrimSpace(req.GetToken())
	newPassword := req.GetNewPassword()
	if resetToken == "" || newPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "Token and new password are required")
	}

	userID, err := s.cache.Get(ctx, "reset_pw:"+resetToken)
	if err != nil || strings.TrimSpace(userID) == "" {
		return nil, status.Error(codes.InvalidArgument, "Invalid or expired token")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Internal error")
	}

	if _, err := query.User.WithContext(ctx).
		Where(query.User.ID.Eq(userID)).
		Update(query.User.Password, string(hashedPassword)); err != nil {
		s.logger.Error("Failed to update password", "error", err)
		return nil, status.Error(codes.Internal, "Failed to update password")
	}

	_ = s.cache.Del(ctx, "reset_pw:"+resetToken)
	return messageResponse("Password reset successfully"), nil
}
func (s *appServices) GetGoogleLoginUrl(ctx context.Context, _ *appv1.GetGoogleLoginUrlRequest) (*appv1.GetGoogleLoginUrlResponse, error) {
	if err := s.authenticator.RequireInternalCall(ctx); err != nil {
		return nil, err
	}
	if s.googleOauth == nil || strings.TrimSpace(s.googleOauth.ClientID) == "" || strings.TrimSpace(s.googleOauth.RedirectURL) == "" {
		return nil, status.Error(codes.FailedPrecondition, "Google OAuth is not configured")
	}

	state, err := generateOAuthState()
	if err != nil {
		s.logger.Error("Failed to generate Google OAuth state", "error", err)
		return nil, status.Error(codes.Internal, "Failed to start Google login")
	}

	if err := s.cache.Set(ctx, googleOAuthStateCacheKey(state), "1", s.googleStateTTL); err != nil {
		s.logger.Error("Failed to persist Google OAuth state", "error", err)
		return nil, status.Error(codes.Internal, "Failed to start Google login")
	}

	loginURL := s.googleOauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return &appv1.GetGoogleLoginUrlResponse{Url: loginURL}, nil
}
func (s *appServices) CompleteGoogleLogin(ctx context.Context, req *appv1.CompleteGoogleLoginRequest) (*appv1.CompleteGoogleLoginResponse, error) {
	if err := s.authenticator.RequireInternalCall(ctx); err != nil {
		return nil, err
	}
	if s.googleOauth == nil || strings.TrimSpace(s.googleOauth.ClientID) == "" || strings.TrimSpace(s.googleOauth.RedirectURL) == "" {
		return nil, status.Error(codes.FailedPrecondition, "Google OAuth is not configured")
	}

	code := strings.TrimSpace(req.GetCode())
	if code == "" {
		return nil, status.Error(codes.InvalidArgument, "Code is required")
	}

	tokenResp, err := s.googleOauth.Exchange(ctx, code)
	if err != nil {
		s.logger.Error("Failed to exchange Google OAuth token", "error", err)
		return nil, status.Error(codes.Unauthenticated, "exchange_failed")
	}

	client := s.googleOauth.Client(ctx, tokenResp)
	resp, err := client.Get(s.googleUserInfoURL)
	if err != nil {
		s.logger.Error("Failed to fetch Google user info", "error", err)
		return nil, status.Error(codes.Unauthenticated, "userinfo_failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Google user info returned non-200", "status", resp.StatusCode)
		return nil, status.Error(codes.Unauthenticated, "userinfo_failed")
	}

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		s.logger.Error("Failed to decode Google user info", "error", err)
		return nil, status.Error(codes.Internal, "userinfo_parse_failed")
	}

	email := strings.TrimSpace(strings.ToLower(googleUser.Email))
	refUsername := strings.TrimSpace(req.GetRefUsername())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "missing_email")
	}

	u := query.User
	user, err := u.WithContext(ctx).Where(u.Email.Eq(email)).First()
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.logger.Error("Failed to load Google user", "error", err)
			return nil, status.Error(codes.Internal, "load_user_failed")
		}
		referrerID, resolveErr := s.resolveSignupReferrerID(ctx, refUsername, googleUser.Name)
		if resolveErr != nil {
			s.logger.Error("Failed to resolve Google signup referrer", "error", resolveErr)
			return nil, status.Error(codes.Internal, "create_user_failed")
		}
		role := "USER"
		user = &model.User{
			ID:               uuid.New().String(),
			Email:            email,
			Username:         stringPointerOrNil(googleUser.Name),
			GoogleID:         stringPointerOrNil(googleUser.ID),
			Avatar:           stringPointerOrNil(googleUser.Picture),
			Role:             &role,
			ReferredByUserID: referrerID,
			ReferralEligible: model.BoolPtr(true),
		}
		if err := u.WithContext(ctx).Create(user); err != nil {
			s.logger.Error("Failed to create Google user", "error", err)
			return nil, status.Error(codes.Internal, "create_user_failed")
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
			if err := s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
				s.logger.Error("Failed to update Google user", "error", err)
				return nil, status.Error(codes.Internal, "update_user_failed")
			}
			user, err = u.WithContext(ctx).Where(u.ID.Eq(user.ID)).First()
			if err != nil {
				s.logger.Error("Failed to reload Google user", "error", err)
				return nil, status.Error(codes.Internal, "reload_user_failed")
			}
		}
	}

	payload, err := buildUserPayload(ctx, s.db, user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.CompleteGoogleLoginResponse{User: toProtoUser(payload)}, nil
}
