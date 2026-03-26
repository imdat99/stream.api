package app

import (
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
	"stream.api/internal/config"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/middleware"
	adminhandler "stream.api/internal/modules/admin"
	adtemplatesmodule "stream.api/internal/modules/adtemplates"
	authmodule "stream.api/internal/modules/auth"
	"stream.api/internal/modules/common"
	dashboardmodule "stream.api/internal/modules/dashboard"
	domainsmodule "stream.api/internal/modules/domains"
	jobsmodule "stream.api/internal/modules/jobs"
	paymentsmodule "stream.api/internal/modules/payments"
	playerconfigsmodule "stream.api/internal/modules/playerconfigs"
	plansmodule "stream.api/internal/modules/plans"
	usersmodule "stream.api/internal/modules/users"
	videosmodule "stream.api/internal/modules/videos"
	"stream.api/internal/video"
	"stream.api/pkg/cache"
	"stream.api/pkg/logger"
	"stream.api/pkg/storage"
	"stream.api/pkg/token"
)

const defaultGoogleUserInfoURL = common.DefaultGoogleUserInfoURL

type Services struct {
	AuthServiceServer
	AccountServiceServer
	PreferencesServiceServer
	UsageServiceServer
	NotificationsServiceServer
	DomainsServiceServer
	AdTemplatesServiceServer
	PlayerConfigsServiceServer
	PlansServiceServer
	PaymentsServiceServer
	VideosServiceServer
	AdminServiceServer
}

type appServices struct {
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

	runtime               *common.Runtime
	authModule            *authmodule.Module
	usersModule           *usersmodule.Module
	domainsModule         *domainsmodule.Module
	adTemplatesModule     *adtemplatesmodule.Module
	playerConfigsModule   *playerconfigsmodule.Module
	plansModule           *plansmodule.Module
	paymentsModule        *paymentsmodule.Module
	videosModule          *videosmodule.Module
	jobsModule            *jobsmodule.Module
	dashboardModule       *dashboardmodule.Module
	authHandler           *authmodule.Handler
	accountHandler        *usersmodule.AccountHandler
	preferencesHandler    *usersmodule.PreferencesHandler
	usageHandler          *usersmodule.UsageHandler
	notificationsHandler  *usersmodule.NotificationsHandler
	domainsHandler        *domainsmodule.Handler
	adTemplatesHandler    *adtemplatesmodule.Handler
	playerConfigsHandler  *playerconfigsmodule.Handler
	plansHandler          *plansmodule.Handler
	paymentsHandler       *paymentsmodule.Handler
	videosHandler         *videosmodule.Handler
	adminHandler          *adminhandler.Handler
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
	frontendBaseURL := ""
	trustedMarker := ""
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
		frontendBaseURL = cfg.Frontend.BaseURL
		trustedMarker = cfg.Internal.Marker
	}

	service := &appServices{
		db:                db,
		logger:            l,
		authenticator:     middleware.NewAuthenticator(db, l, trustedMarker),
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

	service.initModules()

	return &Services{
		AuthServiceServer:          service.authHandler,
		AccountServiceServer:       service.accountHandler,
		PreferencesServiceServer:   service.preferencesHandler,
		UsageServiceServer:         service.usageHandler,
		NotificationsServiceServer: service.notificationsHandler,
		DomainsServiceServer:       service.domainsHandler,
		AdTemplatesServiceServer:   service.adTemplatesHandler,
		PlayerConfigsServiceServer: service.playerConfigsHandler,
		PlansServiceServer:         service.plansHandler,
		PaymentsServiceServer:      service.paymentsHandler,
		VideosServiceServer:        service.videosHandler,
		AdminServiceServer:         service.adminHandler,
	}
}

type AuthServiceServer interface { appv1.AuthServiceServer }
type AccountServiceServer interface { appv1.AccountServiceServer }
type PreferencesServiceServer interface { appv1.PreferencesServiceServer }
type UsageServiceServer interface { appv1.UsageServiceServer }
type NotificationsServiceServer interface { appv1.NotificationsServiceServer }
type DomainsServiceServer interface { appv1.DomainsServiceServer }
type AdTemplatesServiceServer interface { appv1.AdTemplatesServiceServer }
type PlayerConfigsServiceServer interface { appv1.PlayerConfigsServiceServer }
type PlansServiceServer interface { appv1.PlansServiceServer }
type PaymentsServiceServer interface { appv1.PaymentsServiceServer }
type VideosServiceServer interface { appv1.VideosServiceServer }
type AdminServiceServer interface { appv1.AdminServiceServer }

func (s *appServices) initModules() {
	s.runtime = common.NewRuntime(common.RuntimeOptions{
		DB:                s.db,
		Logger:            s.logger,
		Authenticator:     s.authenticator,
		TokenProvider:     s.tokenProvider,
		Cache:             s.cache,
		GoogleOauth:       s.googleOauth,
		GoogleStateTTL:    s.googleStateTTL,
		GoogleUserInfoURL: s.googleUserInfoURL,
		FrontendBaseURL:   s.frontendBaseURL,
		StorageProvider: func() storage.Provider {
			return s.storageProvider
		},
		VideoService: func() *video.Service {
			return s.videoService
		},
		AgentRuntime: func() video.AgentRuntime {
			return s.agentRuntime
		},
	})

	s.usersModule = usersmodule.New(s.runtime)
	s.authModule = authmodule.New(s.runtime, s.usersModule)
	s.domainsModule = domainsmodule.New(s.runtime)
	s.adTemplatesModule = adtemplatesmodule.New(s.runtime)
	s.playerConfigsModule = playerconfigsmodule.New(s.runtime)
	s.plansModule = plansmodule.New(s.runtime)
	s.paymentsModule = paymentsmodule.New(s.runtime)
	s.videosModule = videosmodule.New(s.runtime)
	s.jobsModule = jobsmodule.New(s.runtime)
	s.dashboardModule = dashboardmodule.New(s.runtime)

	s.authHandler = authmodule.NewHandler(s.authModule)
	s.accountHandler = usersmodule.NewAccountHandler(s.usersModule)
	s.preferencesHandler = usersmodule.NewPreferencesHandler(s.usersModule)
	s.usageHandler = usersmodule.NewUsageHandler(s.usersModule)
	s.notificationsHandler = usersmodule.NewNotificationsHandler(s.usersModule)
	s.domainsHandler = domainsmodule.NewHandler(s.domainsModule)
	s.adTemplatesHandler = adtemplatesmodule.NewHandler(s.adTemplatesModule)
	s.playerConfigsHandler = playerconfigsmodule.NewHandler(s.playerConfigsModule)
	s.plansHandler = plansmodule.NewHandler(s.plansModule)
	s.paymentsHandler = paymentsmodule.NewHandler(s.paymentsModule)
	s.videosHandler = videosmodule.NewHandler(s.videosModule)
	s.adminHandler = adminhandler.NewHandler(s.dashboardModule, s.usersModule, s.videosModule, s.paymentsModule, s.plansModule, s.adTemplatesModule, s.playerConfigsModule, s.jobsModule)
}

var (
	_ = model.Plan{}
)
