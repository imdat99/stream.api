package videos

import (
	"context"
	"strings"

	appv1 "stream.api/internal/gen/proto/app/v1"
)

type Handler struct {
	appv1.UnimplementedVideosServiceServer
	module *Module
}

var _ appv1.VideosServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) GetUploadUrl(ctx context.Context, req *appv1.GetUploadUrlRequest) (*appv1.GetUploadUrlResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.GetUploadURL(ctx, GetUploadURLCommand{UserID: result.UserID, Filename: req.GetFilename()})
	if err != nil {
		return nil, err
	}
	return presentGetUploadURLResponse(payload), nil
}

func (h *Handler) CreateVideo(ctx context.Context, req *appv1.CreateVideoRequest) (*appv1.CreateVideoResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.CreateVideo(ctx, CreateVideoCommand{UserID: result.UserID, Title: req.GetTitle(), Description: req.GetDescription(), URL: req.GetUrl(), Size: req.GetSize(), Duration: req.GetDuration(), Format: req.GetFormat()})
	if err != nil {
		return nil, err
	}
	return presentCreateVideoResponse(*payload), nil
}

func (h *Handler) ListVideos(ctx context.Context, req *appv1.ListVideosRequest) (*appv1.ListVideosResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.ListVideos(ctx, ListVideosQuery{UserID: result.UserID, Page: req.GetPage(), Limit: req.GetLimit(), Search: req.GetSearch(), StatusFilter: req.GetStatus()})
	if err != nil {
		return nil, err
	}
	return presentListVideosResponse(payload), nil
}

func (h *Handler) GetVideo(ctx context.Context, req *appv1.GetVideoRequest) (*appv1.GetVideoResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.GetVideo(ctx, GetVideoQuery{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentGetVideoResponse(*payload), nil
}

func (h *Handler) UpdateVideo(ctx context.Context, req *appv1.UpdateVideoRequest) (*appv1.UpdateVideoResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := h.module.UpdateVideo(ctx, UpdateVideoCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId()), Title: req.GetTitle(), Description: req.Description, URL: req.GetUrl(), Size: req.GetSize(), Duration: req.GetDuration(), Format: req.Format, Status: req.Status})
	if err != nil {
		return nil, err
	}
	return presentUpdateVideoResponse(*payload), nil
}

func (h *Handler) DeleteVideo(ctx context.Context, req *appv1.DeleteVideoRequest) (*appv1.MessageResponse, error) {
	result, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.module.DeleteVideo(ctx, DeleteVideoCommand{UserID: result.UserID, ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Video deleted successfully"}, nil
}

func (h *Handler) ListAdminVideos(ctx context.Context, req *appv1.ListAdminVideosRequest) (*appv1.ListAdminVideosResponse, error) {
	payload, err := h.module.ListAdminVideos(ctx, ListAdminVideosQuery{Page: req.GetPage(), Limit: req.GetLimit(), Search: req.GetSearch(), UserID: req.GetUserId(), StatusFilter: req.GetStatus()})
	if err != nil {
		return nil, err
	}
	return presentListAdminVideosResponse(payload), nil
}

func (h *Handler) GetAdminVideo(ctx context.Context, req *appv1.GetAdminVideoRequest) (*appv1.GetAdminVideoResponse, error) {
	payload, err := h.module.GetAdminVideo(ctx, GetAdminVideoQuery{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, err
	}
	return presentGetAdminVideoResponse(*payload), nil
}

func (h *Handler) CreateAdminVideo(ctx context.Context, req *appv1.CreateAdminVideoRequest) (*appv1.CreateAdminVideoResponse, error) {
	payload, err := h.module.CreateAdminVideo(ctx, CreateAdminVideoCommand{UserID: req.GetUserId(), Title: req.GetTitle(), Description: req.Description, URL: req.GetUrl(), Size: req.GetSize(), Duration: req.GetDuration(), Format: req.GetFormat(), AdTemplateID: req.AdTemplateId})
	if err != nil {
		return nil, err
	}
	return presentCreateAdminVideoResponse(*payload), nil
}

func (h *Handler) UpdateAdminVideo(ctx context.Context, req *appv1.UpdateAdminVideoRequest) (*appv1.UpdateAdminVideoResponse, error) {
	payload, err := h.module.UpdateAdminVideo(ctx, UpdateAdminVideoCommand{ID: strings.TrimSpace(req.GetId()), UserID: req.GetUserId(), Title: req.GetTitle(), Description: req.Description, URL: req.GetUrl(), Size: req.GetSize(), Duration: req.GetDuration(), Format: req.GetFormat(), Status: req.GetStatus(), AdTemplateID: req.AdTemplateId})
	if err != nil {
		return nil, err
	}
	return presentUpdateAdminVideoResponse(*payload), nil
}

func (h *Handler) DeleteAdminVideo(ctx context.Context, req *appv1.DeleteAdminVideoRequest) (*appv1.MessageResponse, error) {
	if err := h.module.DeleteAdminVideo(ctx, DeleteAdminVideoCommand{ID: strings.TrimSpace(req.GetId())}); err != nil {
		return nil, err
	}
	return &appv1.MessageResponse{Message: "Video deleted"}, nil
}
