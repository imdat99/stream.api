package service

import (
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/middleware"
	"stream.api/internal/video"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"
)

const adTemplateUpgradeRequiredMessage = "Upgrade required to manage Ads & VAST"
const defaultGoogleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

const (
	playerConfigFreePlanLimitMessage          = "Free plan supports only 1 player config"
	playerConfigFreePlanReconciliationMessage = "Delete extra player configs to continue managing player configs on the free plan"
)

const (
	walletTransactionTypeTopup             = "topup"
	walletTransactionTypeSubscriptionDebit = "subscription_debit"
	walletTransactionTypeReferralReward    = "referral_reward"
	paymentMethodWallet                    = "wallet"
	paymentMethodTopup                     = "topup"
	paymentKindSubscription                = "subscription"
	paymentKindWalletTopup                 = "wallet_topup"
	defaultReferralRewardBps               = int32(500)
)

var allowedTermMonths = map[int32]struct{}{
	1:  {},
	3:  {},
	6:  {},
	12: {},
}

type Services struct {
	appv1.AuthServer
	appv1.AccountServer
	appv1.UsageServer
	appv1.NotificationsServer
	appv1.DomainsServer
	appv1.AdTemplatesServer
	appv1.PlayerConfigsServer
	appv1.PlansServer
	appv1.PaymentsServer
	appv1.VideosServer
	appv1.AdminServer
}

type appServices struct {
	appv1.UnimplementedAuthServer
	appv1.UnimplementedAccountServer
	appv1.UnimplementedUsageServer
	appv1.UnimplementedNotificationsServer
	appv1.UnimplementedDomainsServer
	appv1.UnimplementedAdTemplatesServer
	appv1.UnimplementedPlayerConfigsServer
	appv1.UnimplementedPlansServer
	appv1.UnimplementedPaymentsServer
	appv1.UnimplementedVideosServer
	appv1.UnimplementedAdminServer

	db                *gorm.DB
	logger            logger.Logger
	authenticator     *middleware.Authenticator
	tokenProvider     token.Provider
	cache             cache.Cache
	storageProvider   storage.Provider
	videoService      *video.Service
	agentRuntime      video.AgentRuntime
	googleOauth       *oauth2.Config
	googleStateTTL    time.Duration
	googleUserInfoURL string
	frontendBaseURL   string
}

type paymentInvoiceDetails struct {
	PlanName      string
	TermMonths    *int32
	PaymentMethod string
	ExpiresAt     *time.Time
	WalletAmount  float64
	TopupAmount   float64
}

type paymentExecutionInput struct {
	UserID        string
	Plan          *model.Plan
	TermMonths    int32
	PaymentMethod string
	TopupAmount   *float64
}

type paymentExecutionResult struct {
	Payment       *model.Payment
	Subscription  *model.PlanSubscription
	WalletBalance float64
	InvoiceID     string
}

type referralRewardResult struct {
	Granted bool
	Amount  float64
}

type apiErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func NewServices(c cache.Cache, t token.Provider, db *gorm.DB, l logger.Logger, cfg *config.Config, videoService *video.Service, agentRuntime video.AgentRuntime) *Services {
	var storageProvider storage.Provider
	if cfg != nil {
		provider, err := storage.NewS3Provider(cfg)
		if err != nil {
			l.Error("Failed to initialize S3 provider for gRPC app services", "error", err)
		} else {
			storageProvider = provider
		}
	}

	googleStateTTL := 10 * time.Minute
	googleOauth := &oauth2.Config{}
	if cfg != nil {
		if cfg.Google.StateTTLMinute > 0 {
			googleStateTTL = time.Duration(cfg.Google.StateTTLMinute) * time.Minute
		}
		googleOauth = &oauth2.Config{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			RedirectURL:  cfg.Google.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		}
	}

	frontendBaseURL := ""
	if cfg != nil {
		frontendBaseURL = cfg.Frontend.BaseURL
	}

	service := &appServices{
		db:                db,
		logger:            l,
		authenticator:     middleware.NewAuthenticator(db, l, cfg.Internal.Marker),
		tokenProvider:     t,
		cache:             c,
		storageProvider:   storageProvider,
		videoService:      videoService,
		agentRuntime:      agentRuntime,
		googleOauth:       googleOauth,
		googleStateTTL:    googleStateTTL,
		googleUserInfoURL: defaultGoogleUserInfoURL,
		frontendBaseURL:   frontendBaseURL,
	}
	return &Services{
		AuthServer:          service,
		AccountServer:       service,
		UsageServer:         service,
		NotificationsServer: service,
		DomainsServer:       service,
		AdTemplatesServer:   service,
		PlayerConfigsServer: service,
		PlansServer:         service,
		PaymentsServer:      service,
		VideosServer:        service,
		AdminServer:         service,
	}
}
