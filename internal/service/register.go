package service

import (
	"google.golang.org/grpc"
	appv1 "stream.api/internal/api/proto/app/v1"
)

func Register(server grpc.ServiceRegistrar, services *Services) {
	appv1.RegisterAuthServer(server, services.AuthServer)
	appv1.RegisterAccountServer(server, services.AccountServer)
	appv1.RegisterUsageServer(server, services.UsageServer)
	appv1.RegisterNotificationsServer(server, services.NotificationsServer)
	appv1.RegisterDomainsServer(server, services.DomainsServer)
	appv1.RegisterAdTemplatesServer(server, services.AdTemplatesServer)
	appv1.RegisterPlayerConfigsServer(server, services.PlayerConfigsServer)
	appv1.RegisterPlansServer(server, services.PlansServer)
	appv1.RegisterPaymentsServer(server, services.PaymentsServer)
	appv1.RegisterVideosServer(server, services.VideosServer)
	appv1.RegisterAdminServer(server, services.AdminServer)
}
