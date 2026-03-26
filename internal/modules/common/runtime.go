package common

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/middleware"
	videodomain "stream.api/internal/video"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"
)

const (
	AdTemplateUpgradeRequiredMessage          = "Upgrade required to manage Ads & VAST"
	DefaultGoogleUserInfoURL                 = "https://www.googleapis.com/oauth2/v2/userinfo"
	PlayerConfigFreePlanLimitMessage         = "Free plan supports only 1 player config"
	PlayerConfigFreePlanReconciliationMessage = "Delete extra player configs to continue managing player configs on the free plan"
	WalletTransactionTypeTopup               = "topup"
	WalletTransactionTypeSubscriptionDebit   = "subscription_debit"
	WalletTransactionTypeReferralReward      = "referral_reward"
	PaymentMethodWallet                      = "wallet"
	PaymentMethodTopup                       = "topup"
	PaymentKindSubscription                  = "subscription"
	PaymentKindWalletTopup                   = "wallet_topup"
	DefaultReferralRewardBps                = int32(500)
)

var AllowedTermMonths = map[int32]struct{}{
	1:  {},
	3:  {},
	6:  {},
	12: {},
}

type RuntimeOptions struct {
	DB                *gorm.DB
	Logger            logger.Logger
	Authenticator     *middleware.Authenticator
	TokenProvider     token.Provider
	Cache             cache.Cache
	GoogleOauth       *oauth2.Config
	GoogleStateTTL    time.Duration
	GoogleUserInfoURL string
	FrontendBaseURL   string
	StorageProvider   func() storage.Provider
	VideoService      func() *videodomain.Service
	AgentRuntime      func() videodomain.AgentRuntime
}

type Runtime struct {
	db                  *gorm.DB
	logger              logger.Logger
	authenticator       *middleware.Authenticator
	tokenProvider       token.Provider
	cache               cache.Cache
	googleOauth         *oauth2.Config
	googleStateTTL      time.Duration
	googleUserInfoURL   string
	frontendBaseURL     string
	storageProvider     func() storage.Provider
	videoService        func() *videodomain.Service
	agentRuntime        func() videodomain.AgentRuntime
}

func NewRuntime(opts RuntimeOptions) *Runtime {
	googleStateTTL := opts.GoogleStateTTL
	if googleStateTTL <= 0 {
		googleStateTTL = 10 * time.Minute
	}
	googleUserInfoURL := strings.TrimSpace(opts.GoogleUserInfoURL)
	if googleUserInfoURL == "" {
		googleUserInfoURL = DefaultGoogleUserInfoURL
	}
	return &Runtime{
		db:                opts.DB,
		logger:            opts.Logger,
		authenticator:     opts.Authenticator,
		tokenProvider:     opts.TokenProvider,
		cache:             opts.Cache,
		googleOauth:       opts.GoogleOauth,
		googleStateTTL:    googleStateTTL,
		googleUserInfoURL: googleUserInfoURL,
		frontendBaseURL:   strings.TrimSpace(opts.FrontendBaseURL),
		storageProvider:   opts.StorageProvider,
		videoService:      opts.VideoService,
		agentRuntime:      opts.AgentRuntime,
	}
}

func (r *Runtime) DB() *gorm.DB { return r.db }
func (r *Runtime) Logger() logger.Logger { return r.logger }
func (r *Runtime) Authenticator() *middleware.Authenticator { return r.authenticator }
func (r *Runtime) TokenProvider() token.Provider { return r.tokenProvider }
func (r *Runtime) Cache() cache.Cache { return r.cache }
func (r *Runtime) GoogleOauth() *oauth2.Config { return r.googleOauth }
func (r *Runtime) GoogleStateTTL() time.Duration { return r.googleStateTTL }
func (r *Runtime) GoogleUserInfoURL() string { return r.googleUserInfoURL }
func (r *Runtime) FrontendBaseURL() string { return r.frontendBaseURL }

func (r *Runtime) StorageProvider() storage.Provider {
	if r == nil || r.storageProvider == nil {
		return nil
	}
	return r.storageProvider()
}

func (r *Runtime) VideoService() *videodomain.Service {
	if r == nil || r.videoService == nil {
		return nil
	}
	return r.videoService()
}

func (r *Runtime) AgentRuntime() videodomain.AgentRuntime {
	if r == nil || r.agentRuntime == nil {
		return nil
	}
	return r.agentRuntime()
}

func (r *Runtime) Authenticate(ctx context.Context) (*middleware.AuthResult, error) {
	if r == nil || r.authenticator == nil {
		return nil, status.Error(codes.Unauthenticated, "Unauthorized")
	}
	return r.authenticator.Authenticate(ctx)
}

func (r *Runtime) RequireAdmin(ctx context.Context) (*middleware.AuthResult, error) {
	result, err := r.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if result.User == nil || result.User.Role == nil || strings.ToUpper(strings.TrimSpace(*result.User.Role)) != "ADMIN" {
		return nil, status.Error(codes.PermissionDenied, "Admin access required")
	}
	return result, nil
}

func (r *Runtime) IssueSessionCookies(ctx context.Context, user *model.User) error {
	if user == nil {
		return status.Error(codes.Unauthenticated, "Unauthorized")
	}
	if r == nil || r.tokenProvider == nil || r.cache == nil {
		return status.Error(codes.Internal, "Error storing session")
	}
	tokenPair, err := r.tokenProvider.GenerateTokenPair(user.ID, user.Email, SafeRole(user.Role))
	if err != nil {
		if r.logger != nil {
			r.logger.Error("Token generation failed", "error", err)
		}
		return status.Error(codes.Internal, "Error generating tokens")
	}
	if err := r.cache.Set(ctx, "refresh_uuid:"+tokenPair.RefreshUUID, user.ID, time.Until(time.Unix(tokenPair.RtExpires, 0))); err != nil {
		if r.logger != nil {
			r.logger.Error("Session storage failed", "error", err)
		}
		return status.Error(codes.Internal, "Error storing session")
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs(
		"set-cookie", BuildTokenCookie("access_token", tokenPair.AccessToken, int(tokenPair.AtExpires-time.Now().Unix())),
		"set-cookie", BuildTokenCookie("refresh_token", tokenPair.RefreshToken, int(tokenPair.RtExpires-time.Now().Unix())),
	)); err != nil && r.logger != nil {
		r.logger.Error("Failed to set gRPC auth headers", "error", err)
	}
	return nil
}

func BuildTokenCookie(name string, value string, maxAge int) string {
	return (&http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
	}).String()
}
