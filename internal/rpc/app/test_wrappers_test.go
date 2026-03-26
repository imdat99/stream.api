package app

import (
	"context"

	appv1 "stream.api/internal/gen/proto/app/v1"
	paymentsmodule "stream.api/internal/modules/payments"
	playerconfigsmodule "stream.api/internal/modules/playerconfigs"
)

func (s *appServices) Register(ctx context.Context, req *appv1.RegisterRequest) (*appv1.RegisterResponse, error) {
	return s.authModule.Register(ctx, req)
}

func (s *appServices) TopupWallet(ctx context.Context, req *appv1.TopupWalletRequest) (*appv1.TopupWalletResponse, error) {
	return paymentsmodule.NewHandler(s.paymentsModule).TopupWallet(ctx, req)
}

func (s *appServices) UpdateAdminUserReferralSettings(ctx context.Context, req *appv1.UpdateAdminUserReferralSettingsRequest) (*appv1.UpdateAdminUserReferralSettingsResponse, error) {
	return s.usersModule.UpdateAdminUserReferralSettings(ctx, req)
}

func (s *appServices) CreatePlayerConfig(ctx context.Context, req *appv1.CreatePlayerConfigRequest) (*appv1.CreatePlayerConfigResponse, error) {
	return playerconfigsmodule.NewHandler(s.playerConfigsModule).CreatePlayerConfig(ctx, req)
}

func (s *appServices) UpdatePlayerConfig(ctx context.Context, req *appv1.UpdatePlayerConfigRequest) (*appv1.UpdatePlayerConfigResponse, error) {
	return playerconfigsmodule.NewHandler(s.playerConfigsModule).UpdatePlayerConfig(ctx, req)
}

func (s *appServices) DeletePlayerConfig(ctx context.Context, req *appv1.DeletePlayerConfigRequest) (*appv1.MessageResponse, error) {
	return playerconfigsmodule.NewHandler(s.playerConfigsModule).DeletePlayerConfig(ctx, req)
}
