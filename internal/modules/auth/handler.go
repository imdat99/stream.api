package auth

import (
	"context"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	appv1.UnimplementedAuthServiceServer
	module *Module
}

var _ appv1.AuthServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler {
	return &Handler{module: module}
}

func (h *Handler) Login(ctx context.Context, req *appv1.LoginRequest) (*appv1.LoginResponse, error) {
	return h.module.Login(ctx, req)
}

func (h *Handler) Register(ctx context.Context, req *appv1.RegisterRequest) (*appv1.RegisterResponse, error) {
	return h.module.Register(ctx, req)
}

func (h *Handler) Logout(ctx context.Context, req *appv1.LogoutRequest) (*appv1.MessageResponse, error) {
	return h.module.Logout(ctx, req)
}

func (h *Handler) ChangePassword(ctx context.Context, req *appv1.ChangePasswordRequest) (*appv1.MessageResponse, error) {
	return h.module.ChangePassword(ctx, req)
}

func (h *Handler) ForgotPassword(ctx context.Context, req *appv1.ForgotPasswordRequest) (*appv1.MessageResponse, error) {
	return h.module.ForgotPassword(ctx, req)
}

func (h *Handler) ResetPassword(ctx context.Context, req *appv1.ResetPasswordRequest) (*appv1.MessageResponse, error) {
	return h.module.ResetPassword(ctx, req)
}

func (h *Handler) GetGoogleLoginUrl(ctx context.Context, req *appv1.GetGoogleLoginUrlRequest) (*appv1.GetGoogleLoginUrlResponse, error) {
	return h.module.GetGoogleLoginURL(ctx, req)
}

func (h *Handler) CompleteGoogleLogin(ctx context.Context, req *appv1.CompleteGoogleLoginRequest) (*appv1.CompleteGoogleLoginResponse, error) {
	return h.module.CompleteGoogleLogin(ctx, req)
}
