package videos

import (
	"time"

	appv1 "stream.api/internal/gen/proto/app/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"stream.api/internal/modules/common"
)

func presentGetUploadURLResponse(result *GetUploadURLResult) *appv1.GetUploadUrlResponse {
	return &appv1.GetUploadUrlResponse{UploadUrl: result.UploadURL, Key: result.Key, FileId: result.FileID}
}

func presentVideo(view VideoView) *appv1.Video {
	if view.JobID != nil {
		return common.ToProtoVideo(view.Video, *view.JobID)
	}
	return common.ToProtoVideo(view.Video)
}

func presentCreateVideoResponse(view VideoView) *appv1.CreateVideoResponse {
	return &appv1.CreateVideoResponse{Video: presentVideo(view)}
}

func presentListVideosResponse(result *ListVideosResult) *appv1.ListVideosResponse {
	items := make([]*appv1.Video, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentVideo(item))
	}
	return &appv1.ListVideosResponse{Videos: items, Total: result.Total, Page: result.Page, Limit: result.Limit}
}

func presentGetVideoResponse(view VideoView) *appv1.GetVideoResponse {
	return &appv1.GetVideoResponse{Video: presentVideo(view)}
}

func presentUpdateVideoResponse(view VideoView) *appv1.UpdateVideoResponse {
	return &appv1.UpdateVideoResponse{Video: presentVideo(view)}
}

func presentAdminVideo(view AdminVideoView) *appv1.AdminVideo {
	return &appv1.AdminVideo{
		Id:               view.ID,
		UserId:           view.UserID,
		Title:            view.Title,
		Description:      view.Description,
		Url:              view.URL,
		Status:           view.Status,
		Size:             view.Size,
		Duration:         view.Duration,
		Format:           view.Format,
		CreatedAt:        parseRFC3339ToProto(view.CreatedAt),
		UpdatedAt:        parseRFC3339ToProto(view.UpdatedAt),
		ProcessingStatus: view.ProcessingStatus,
		JobId:            view.JobID,
		OwnerEmail:       view.OwnerEmail,
		AdTemplateId:     view.AdTemplateID,
		AdTemplateName:   view.AdTemplateName,
	}
}

func presentListAdminVideosResponse(result *ListAdminVideosResult) *appv1.ListAdminVideosResponse {
	items := make([]*appv1.AdminVideo, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdminVideo(item))
	}
	return &appv1.ListAdminVideosResponse{Videos: items, Total: result.Total, Page: result.Page, Limit: result.Limit}
}

func presentGetAdminVideoResponse(view AdminVideoView) *appv1.GetAdminVideoResponse {
	return &appv1.GetAdminVideoResponse{Video: presentAdminVideo(view)}
}

func presentCreateAdminVideoResponse(view AdminVideoView) *appv1.CreateAdminVideoResponse {
	return &appv1.CreateAdminVideoResponse{Video: presentAdminVideo(view)}
}

func presentUpdateAdminVideoResponse(view AdminVideoView) *appv1.UpdateAdminVideoResponse {
	return &appv1.UpdateAdminVideoResponse{Video: presentAdminVideo(view)}
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
