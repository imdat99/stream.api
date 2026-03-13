//go:build ignore
// +build ignore

package auth

import "github.com/gin-gonic/gin"

// AuthHandler defines the interface for authentication operations
type AuthHandler interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Register(c *gin.Context)
	ForgotPassword(c *gin.Context)
	ResetPassword(c *gin.Context)
	LoginGoogle(c *gin.Context)
	GoogleCallback(c *gin.Context)
	GetMe(c *gin.Context)
	UpdateMe(c *gin.Context)
	ChangePassword(c *gin.Context)
	DeleteMe(c *gin.Context)
	ClearMyData(c *gin.Context)
}

// LoginRequest defines the payload for login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest defines the payload for registration
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Username string `json:"username" binding:"required"`
}

// ForgotPasswordRequest defines the payload for requesting a password reset
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest defines the payload for resetting the password
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

type UpdateMeRequest struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Language *string `json:"language"`
	Locale   *string `json:"locale"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=6"`
}
