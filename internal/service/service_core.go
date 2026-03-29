package service

import (
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
	"stream.api/internal/adapters/redis"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	"stream.api/internal/middleware"
	"stream.api/internal/repository"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
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
	appv1.NotificationsServer
	appv1.DomainsServer
	appv1.AdTemplatesServer
	appv1.PopupAdsServer
	appv1.PlayerConfigsServer
	appv1.PlansServer
	appv1.PaymentsServer
	appv1.VideosServer
	appv1.AdminServer
}

type authAppService struct{ *appServices }
type accountAppService struct{ *appServices }
type notificationsAppService struct{ *appServices }
type domainsAppService struct{ *appServices }
type adTemplatesAppService struct{ *appServices }
type popupAdsAppService struct{ *appServices }
type playerConfigsAppService struct{ *appServices }
type plansAppService struct{ *appServices }
type paymentsAppService struct{ *appServices }
type videosAppService struct{ *appServices }
type adminAppService struct{ *appServices }

type appServices struct {
	appv1.UnimplementedAuthServer
	appv1.UnimplementedAccountServer
	appv1.UnimplementedNotificationsServer
	appv1.UnimplementedDomainsServer
	appv1.UnimplementedAdTemplatesServer
	appv1.UnimplementedPopupAdsServer
	appv1.UnimplementedPlayerConfigsServer
	appv1.UnimplementedPlansServer
	appv1.UnimplementedPaymentsServer
	appv1.UnimplementedVideosServer
	appv1.UnimplementedAdminServer

	db                   *gorm.DB
	logger               logger.Logger
	authenticator        *middleware.Authenticator
	cache                *redis.RedisAdapter
	storageProvider      storage.Provider
	videoWorkflowService VideoWorkflow
	videoRepository      VideoRepository
	userRepository       UserRepository
	preferenceRepository UserPreferenceRepository
	billingRepository    BillingRepository
	planRepository       PlanRepository
	paymentRepository    PaymentRepository
	accountRepository    AccountRepository
	notificationRepo     NotificationRepository
	notificationEvents   NotificationEventPublisher
	domainRepository     DomainRepository
	adTemplateRepository AdTemplateRepository
	popupAdRepository    PopupAdRepository
	playerConfigRepo     PlayerConfigRepository
	agentRuntime         AgentRuntime
	googleOauth          *oauth2.Config
	googleStateTTL       time.Duration
	googleUserInfoURL    string
	frontendBaseURL      string
	jobRepository        JobRepository
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

func NewServices(c *redis.RedisAdapter, db *gorm.DB, l logger.Logger, cfg *config.Config, videoWorkflowService VideoWorkflow, agentRuntime AgentRuntime, notificationEvents NotificationEventPublisher) *Services {
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
		db:                   db,
		logger:               l,
		authenticator:        middleware.NewAuthenticator(db, l, cfg.Internal.Marker, notificationEvents),
		cache:                c,
		storageProvider:      storageProvider,
		videoWorkflowService: videoWorkflowService,
		videoRepository:      repository.NewVideoRepository(db),
		userRepository:       repository.NewUserRepository(db),
		preferenceRepository: repository.NewUserPreferenceRepository(db),
		billingRepository:    repository.NewBillingRepository(db),
		planRepository:       repository.NewPlanRepository(db),
		paymentRepository:    repository.NewPaymentRepository(db),
		accountRepository:    repository.NewAccountRepository(db),
		notificationRepo:     repository.NewNotificationRepository(db),
		notificationEvents:   notificationEvents,
		domainRepository:     repository.NewDomainRepository(db),
		adTemplateRepository: repository.NewAdTemplateRepository(db),
		popupAdRepository:    repository.NewPopupAdRepository(db),
		playerConfigRepo:     repository.NewPlayerConfigRepository(db),
		jobRepository:        repository.NewJobRepository(db),
		agentRuntime:         agentRuntime,
		googleOauth:          googleOauth,
		googleStateTTL:       googleStateTTL,
		googleUserInfoURL:    defaultGoogleUserInfoURL,
		frontendBaseURL:      frontendBaseURL,
	}
	return &Services{
		AuthServer:          &authAppService{appServices: service},
		AccountServer:       &accountAppService{appServices: service},
		NotificationsServer: &notificationsAppService{appServices: service},
		DomainsServer:       &domainsAppService{appServices: service},
		AdTemplatesServer:   &adTemplatesAppService{appServices: service},
		PopupAdsServer:      &popupAdsAppService{appServices: service},
		PlayerConfigsServer: &playerConfigsAppService{appServices: service},
		PlansServer:         &plansAppService{appServices: service},
		PaymentsServer:      &paymentsAppService{appServices: service},
		VideosServer:        &videosAppService{appServices: service},
		AdminServer:         &adminAppService{appServices: service},
	}
}
