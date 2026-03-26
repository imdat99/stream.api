package videos

import "stream.api/internal/database/model"

type GetUploadURLCommand struct {
	UserID   string
	Filename string
}

type GetUploadURLResult struct {
	UploadURL string
	Key       string
	FileID    string
}

type CreateVideoCommand struct {
	UserID      string
	Title       string
	Description string
	URL         string
	Size        int64
	Duration    int32
	Format      string
}

type VideoView struct {
	Video *model.Video
	JobID *string
}

type ListVideosQuery struct {
	UserID       string
	Page         int32
	Limit        int32
	Search       string
	StatusFilter string
}

type ListVideosResult struct {
	Items []VideoView
	Total int64
	Page  int32
	Limit int32
}

type GetVideoQuery struct {
	UserID string
	ID     string
}

type UpdateVideoCommand struct {
	UserID      string
	ID          string
	Title       string
	Description *string
	URL         string
	Size        int64
	Duration    int32
	Format      *string
	Status      *string
}

type DeleteVideoCommand struct {
	UserID string
	ID     string
}

type AdminVideoView struct {
	ID               string
	UserID           string
	Title            string
	Description      *string
	URL              string
	Status           string
	Size             int64
	Duration         int32
	Format           string
	CreatedAt        *string
	UpdatedAt        *string
	ProcessingStatus *string
	JobID            *string
	OwnerEmail       *string
	AdTemplateID     *string
	AdTemplateName   *string
}

type ListAdminVideosQuery struct {
	Page         int32
	Limit        int32
	Search       string
	UserID       string
	StatusFilter string
}

type ListAdminVideosResult struct {
	Items []AdminVideoView
	Total int64
	Page  int32
	Limit int32
}

type GetAdminVideoQuery struct {
	ID string
}

type CreateAdminVideoCommand struct {
	UserID       string
	Title        string
	Description  *string
	URL          string
	Size         int64
	Duration     int32
	Format       string
	AdTemplateID *string
}

type UpdateAdminVideoCommand struct {
	ID           string
	UserID       string
	Title        string
	Description  *string
	URL          string
	Size         int64
	Duration     int32
	Format       string
	Status       string
	AdTemplateID *string
}

type DeleteAdminVideoCommand struct {
	ID string
}
