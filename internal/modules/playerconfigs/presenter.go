package playerconfigs

import (
	"time"

	appv1 "stream.api/internal/gen/proto/app/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"stream.api/internal/modules/common"
)

func presentPlayerConfig(view PlayerConfigView) *appv1.PlayerConfig {
	return common.ToProtoPlayerConfig(view.Config)
}

func presentListPlayerConfigsResponse(result *ListPlayerConfigsResult) *appv1.ListPlayerConfigsResponse {
	items := make([]*appv1.PlayerConfig, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentPlayerConfig(item))
	}
	return &appv1.ListPlayerConfigsResponse{Configs: items}
}

func presentCreatePlayerConfigResponse(view PlayerConfigView) *appv1.CreatePlayerConfigResponse {
	return &appv1.CreatePlayerConfigResponse{Config: presentPlayerConfig(view)}
}

func presentUpdatePlayerConfigResponse(view PlayerConfigView) *appv1.UpdatePlayerConfigResponse {
	return &appv1.UpdatePlayerConfigResponse{Config: presentPlayerConfig(view)}
}

func presentAdminPlayerConfig(view AdminPlayerConfigView) *appv1.AdminPlayerConfig {
	return &appv1.AdminPlayerConfig{
		Id:            view.ID,
		UserId:        view.UserID,
		Name:          view.Name,
		Description:   view.Description,
		Autoplay:      view.Autoplay,
		Loop:          view.Loop,
		Muted:         view.Muted,
		ShowControls:  view.ShowControls,
		Pip:           view.Pip,
		Airplay:       view.Airplay,
		Chromecast:    view.Chromecast,
		IsActive:      view.IsActive,
		IsDefault:     view.IsDefault,
		OwnerEmail:    view.OwnerEmail,
		CreatedAt:     parseRFC3339ToProto(view.CreatedAt),
		UpdatedAt:     parseRFC3339ToProto(view.UpdatedAt),
		EncrytionM3U8: view.EncrytionM3U8,
		LogoUrl:       view.LogoURL,
	}
}

func presentListAdminPlayerConfigsResponse(result *ListAdminPlayerConfigsResult) *appv1.ListAdminPlayerConfigsResponse {
	items := make([]*appv1.AdminPlayerConfig, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdminPlayerConfig(item))
	}
	return &appv1.ListAdminPlayerConfigsResponse{Configs: items, Total: result.Total, Page: result.Page, Limit: result.Limit}
}

func presentGetAdminPlayerConfigResponse(view AdminPlayerConfigView) *appv1.GetAdminPlayerConfigResponse {
	return &appv1.GetAdminPlayerConfigResponse{Config: presentAdminPlayerConfig(view)}
}

func presentCreateAdminPlayerConfigResponse(view AdminPlayerConfigView) *appv1.CreateAdminPlayerConfigResponse {
	return &appv1.CreateAdminPlayerConfigResponse{Config: presentAdminPlayerConfig(view)}
}

func presentUpdateAdminPlayerConfigResponse(view AdminPlayerConfigView) *appv1.UpdateAdminPlayerConfigResponse {
	return &appv1.UpdateAdminPlayerConfigResponse{Config: presentAdminPlayerConfig(view)}
}

func parseRFC3339ToProto(value *string) *timestamppb.Timestamp {
	if value == nil || *value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return nil
	}
	return timestamppb.New(parsed.UTC())
}
