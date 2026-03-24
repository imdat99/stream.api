package app

import (
	"google.golang.org/grpc"
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func Register(server grpc.ServiceRegistrar, services *Services) {
	appv1.RegisterAuthServiceServer(server, services.AuthServiceServer)
	appv1.RegisterAccountServiceServer(server, services.AccountServiceServer)
	appv1.RegisterPreferencesServiceServer(server, services.PreferencesServiceServer)
	appv1.RegisterUsageServiceServer(server, services.UsageServiceServer)
	appv1.RegisterNotificationsServiceServer(server, services.NotificationsServiceServer)
	appv1.RegisterDomainsServiceServer(server, services.DomainsServiceServer)
	appv1.RegisterAdTemplatesServiceServer(server, services.AdTemplatesServiceServer)
	appv1.RegisterPlayerConfigsServiceServer(server, services.PlayerConfigsServiceServer)
	appv1.RegisterPlansServiceServer(server, services.PlansServiceServer)
	appv1.RegisterPaymentsServiceServer(server, services.PaymentsServiceServer)
	appv1.RegisterVideosServiceServer(server, services.VideosServiceServer)
	appv1.RegisterAdminServiceServer(server, services.AdminServiceServer)
}
