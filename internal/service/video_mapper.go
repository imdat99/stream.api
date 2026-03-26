package service

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func toProtoVideo(item *model.Video, jobID ...string) *appv1.Video {
	if item == nil {
		return nil
	}
	statusValue := stringValue(item.Status)
	if statusValue == "" {
		statusValue = "ready"
	}
	var linkedJobID *string
	if len(jobID) > 0 {
		linkedJobID = stringPointerOrNil(jobID[0])
	}
	return &appv1.Video{
		Id:               item.ID,
		UserId:           item.UserID,
		Title:            item.Title,
		Description:      item.Description,
		Url:              item.URL,
		Status:           strings.ToLower(statusValue),
		Size:             item.Size,
		Duration:         item.Duration,
		Format:           item.Format,
		Thumbnail:        item.Thumbnail,
		ProcessingStatus: item.ProcessingStatus,
		StorageType:      item.StorageType,
		CreatedAt:        timeToProto(item.CreatedAt),
		UpdatedAt:        timestamppb.New(item.UpdatedAt.UTC()),
		JobId:            linkedJobID,
	}
}

func (s *videosAppService) buildVideo(ctx context.Context, video *model.Video) (*appv1.Video, error) {
	if video == nil {
		return nil, nil
	}
	jobID, err := s.loadLatestVideoJobID(ctx, video.ID)
	if err != nil {
		return nil, err
	}
	if jobID != nil {
		return toProtoVideo(video, *jobID), nil
	}
	return toProtoVideo(video), nil
}
