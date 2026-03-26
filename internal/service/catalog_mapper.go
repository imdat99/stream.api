package service

import appv1 "stream.api/internal/api/proto/app/v1"
import "stream.api/internal/database/model"

func toProtoDomain(item *model.Domain) *appv1.Domain {
	if item == nil {
		return nil
	}
	return &appv1.Domain{
		Id:        item.ID,
		Name:      item.Name,
		CreatedAt: timeToProto(item.CreatedAt),
		UpdatedAt: timeToProto(item.UpdatedAt),
	}
}

func toProtoAdTemplate(item *model.AdTemplate) *appv1.AdTemplate {
	if item == nil {
		return nil
	}
	return &appv1.AdTemplate{
		Id:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		VastTagUrl:  item.VastTagURL,
		AdFormat:    model.StringValue(item.AdFormat),
		Duration:    int64PtrToInt32Ptr(item.Duration),
		IsActive:    boolValue(item.IsActive),
		IsDefault:   item.IsDefault,
		CreatedAt:   timeToProto(item.CreatedAt),
		UpdatedAt:   timeToProto(item.UpdatedAt),
	}
}

func toProtoPlayerConfig(item *model.PlayerConfig) *appv1.PlayerConfig {
	if item == nil {
		return nil
	}
	return &appv1.PlayerConfig{
		Id:            item.ID,
		Name:          item.Name,
		Description:   item.Description,
		Autoplay:      item.Autoplay,
		Loop:          item.Loop,
		Muted:         item.Muted,
		ShowControls:  boolValue(item.ShowControls),
		Pip:           boolValue(item.Pip),
		Airplay:       boolValue(item.Airplay),
		Chromecast:    boolValue(item.Chromecast),
		IsActive:      boolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(&item.UpdatedAt),
		EncrytionM3U8: boolValue(item.EncrytionM3u8),
		LogoUrl:       nullableTrimmedString(item.LogoURL),
	}
}

func toProtoAdminPlayerConfig(item *model.PlayerConfig, ownerEmail *string) *appv1.AdminPlayerConfig {
	if item == nil {
		return nil
	}
	return &appv1.AdminPlayerConfig{
		Id:            item.ID,
		UserId:        item.UserID,
		Name:          item.Name,
		Description:   item.Description,
		Autoplay:      item.Autoplay,
		Loop:          item.Loop,
		Muted:         item.Muted,
		ShowControls:  boolValue(item.ShowControls),
		Pip:           boolValue(item.Pip),
		Airplay:       boolValue(item.Airplay),
		Chromecast:    boolValue(item.Chromecast),
		IsActive:      boolValue(item.IsActive),
		IsDefault:     item.IsDefault,
		OwnerEmail:    ownerEmail,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(&item.UpdatedAt),
		EncrytionM3U8: boolValue(item.EncrytionM3u8),
		LogoUrl:       nullableTrimmedString(item.LogoURL),
	}
}

func toProtoPlan(item *model.Plan) *appv1.Plan {
	if item == nil {
		return nil
	}
	return &appv1.Plan{
		Id:            item.ID,
		Name:          item.Name,
		Description:   item.Description,
		Price:         item.Price,
		Cycle:         item.Cycle,
		StorageLimit:  item.StorageLimit,
		UploadLimit:   item.UploadLimit,
		DurationLimit: item.DurationLimit,
		QualityLimit:  item.QualityLimit,
		Features:      item.Features,
		IsActive:      boolValue(item.IsActive),
	}
}
