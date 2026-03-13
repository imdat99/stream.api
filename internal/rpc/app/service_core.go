package app

import (
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
	"stream.api/internal/config"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/middleware"
	videogrpc "stream.api/internal/video/runtime/grpc"
	"stream.api/internal/video/runtime/services"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"
)

const adTemplateUpgradeRequiredMessage = "Upgrade required to manage Ads & VAST"

const (
	walletTransactionTypeTopup             = "topup"
	walletTransactionTypeSubscriptionDebit = "subscription_debit"
	paymentMethodWallet                    = "wallet"
	paymentMethodTopup                     = "topup"
	paymentKindSubscription                = "subscription"
	paymentKindWalletTopup                 = "wallet_topup"
)

var allowedTermMonths = map[int32]struct{}{
	1:  {},
	3:  {},
	6:  {},
	12: {},
}

type Services struct {
	AuthServiceServer
	AccountServiceServer
	PreferencesServiceServer
	UsageServiceServer
	NotificationsServiceServer
	DomainsServiceServer
	AdTemplatesServiceServer
	PlansServiceServer
	PaymentsServiceServer
	VideosServiceServer
	AdminServiceServer
}

type appServices struct {
	appv1.UnimplementedAuthServiceServer
	appv1.UnimplementedAccountServiceServer
	appv1.UnimplementedPreferencesServiceServer
	appv1.UnimplementedUsageServiceServer
	appv1.UnimplementedNotificationsServiceServer
	appv1.UnimplementedDomainsServiceServer
	appv1.UnimplementedAdTemplatesServiceServer
	appv1.UnimplementedPlansServiceServer
	appv1.UnimplementedPaymentsServiceServer
	appv1.UnimplementedVideosServiceServer
	appv1.UnimplementedAdminServiceServer

	db              *gorm.DB
	logger          logger.Logger
	authenticator   *middleware.Authenticator
	tokenProvider   token.Provider
	cache           cache.Cache
	storageProvider storage.Provider
	jobService      *services.JobService
	agentRuntime    *videogrpc.Server
	googleOauth     *oauth2.Config
	googleStateTTL  time.Duration
}

type paymentRow struct {
	ID            string     `gorm:"column:id"`
	Amount        float64    `gorm:"column:amount"`
	Currency      *string    `gorm:"column:currency"`
	Status        *string    `gorm:"column:status"`
	PlanID        *string    `gorm:"column:plan_id"`
	PlanName      *string    `gorm:"column:plan_name"`
	TermMonths    *int32     `gorm:"column:term_months"`
	PaymentMethod *string    `gorm:"column:payment_method"`
	ExpiresAt     *time.Time `gorm:"column:expires_at"`
	CreatedAt     *time.Time `gorm:"column:created_at"`
}

type paymentInvoiceDetails struct {
	PlanName      string
	TermMonths    *int32
	PaymentMethod string
	ExpiresAt     *time.Time
	WalletAmount  float64
	TopupAmount   float64
}

type apiErrorBody struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewServices(c cache.Cache, t token.Provider, db *gorm.DB, l logger.Logger, cfg *config.Config, jobService *services.JobService, agentRuntime *videogrpc.Server) *Services {
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

	service := &appServices{
		db:              db,
		logger:          l,
		authenticator:   middleware.NewAuthenticator(db, l, cfg.Internal.Marker),
		tokenProvider:   t,
		cache:           c,
		storageProvider: storageProvider,
		jobService:      jobService,
		agentRuntime:    agentRuntime,
		googleOauth:     googleOauth,
		googleStateTTL:  googleStateTTL,
	}
	return &Services{
		AuthServiceServer:          service,
		AccountServiceServer:       service,
		PreferencesServiceServer:   service,
		UsageServiceServer:         service,
		NotificationsServiceServer: service,
		DomainsServiceServer:       service,
		AdTemplatesServiceServer:   service,
		PlansServiceServer:         service,
		PaymentsServiceServer:      service,
		VideosServiceServer:        service,
		AdminServiceServer:         service,
	}
}

type AuthServiceServer interface {
	appv1.AuthServiceServer
}

type AccountServiceServer interface {
	appv1.AccountServiceServer
}

type PreferencesServiceServer interface {
	appv1.PreferencesServiceServer
}

type UsageServiceServer interface {
	appv1.UsageServiceServer
}

type NotificationsServiceServer interface {
	appv1.NotificationsServiceServer
}

type DomainsServiceServer interface {
	appv1.DomainsServiceServer
}

type AdTemplatesServiceServer interface {
	appv1.AdTemplatesServiceServer
}

type PlansServiceServer interface {
	appv1.PlansServiceServer
}

type PaymentsServiceServer interface {
	appv1.PaymentsServiceServer
}

type VideosServiceServer interface {
	appv1.VideosServiceServer
}

type AdminServiceServer interface {
	appv1.AdminServiceServer
}
