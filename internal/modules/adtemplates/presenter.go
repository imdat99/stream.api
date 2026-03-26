package adtemplates

import (
	"time"

	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func presentAdTemplate(view AdTemplateView) *appv1.AdTemplate {
	return common.ToProtoAdTemplate(view.Template)
}

func presentListAdTemplatesResponse(result *ListAdTemplatesResult) *appv1.ListAdTemplatesResponse {
	items := make([]*appv1.AdTemplate, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdTemplate(item))
	}
	return &appv1.ListAdTemplatesResponse{Templates: items}
}

func presentCreateAdTemplateResponse(view AdTemplateView) *appv1.CreateAdTemplateResponse {
	return &appv1.CreateAdTemplateResponse{Template: presentAdTemplate(view)}
}

func presentUpdateAdTemplateResponse(view AdTemplateView) *appv1.UpdateAdTemplateResponse {
	return &appv1.UpdateAdTemplateResponse{Template: presentAdTemplate(view)}
}

func presentAdminAdTemplate(view AdminAdTemplateView) *appv1.AdminAdTemplate {
	return &appv1.AdminAdTemplate{
		Id:          view.ID,
		UserId:      view.UserID,
		Name:        view.Name,
		Description: view.Description,
		VastTagUrl:  view.VastTagURL,
		AdFormat:    view.AdFormat,
		Duration:    view.Duration,
		IsActive:    view.IsActive,
		IsDefault:   view.IsDefault,
		OwnerEmail:  view.OwnerEmail,
		CreatedAt:   parseRFC3339ToProto(view.CreatedAt),
		UpdatedAt:   parseRFC3339ToProto(view.UpdatedAt),
	}
}

func presentListAdminAdTemplatesResponse(result *ListAdminAdTemplatesResult) *appv1.ListAdminAdTemplatesResponse {
	items := make([]*appv1.AdminAdTemplate, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdminAdTemplate(item))
	}
	return &appv1.ListAdminAdTemplatesResponse{Templates: items, Total: result.Total, Page: result.Page, Limit: result.Limit}
}

func presentGetAdminAdTemplateResponse(view AdminAdTemplateView) *appv1.GetAdminAdTemplateResponse {
	return &appv1.GetAdminAdTemplateResponse{Template: presentAdminAdTemplate(view)}
}

func presentCreateAdminAdTemplateResponse(view AdminAdTemplateView) *appv1.CreateAdminAdTemplateResponse {
	return &appv1.CreateAdminAdTemplateResponse{Template: presentAdminAdTemplate(view)}
}

func presentUpdateAdminAdTemplateResponse(view AdminAdTemplateView) *appv1.UpdateAdminAdTemplateResponse {
	return &appv1.UpdateAdminAdTemplateResponse{Template: presentAdminAdTemplate(view)}
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

func parseRFC3339ToTimePointer(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}
