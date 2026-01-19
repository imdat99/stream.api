package video

import "github.com/gin-gonic/gin"

// VideoHandler defines the interface for video operations
type VideoHandler interface {
	GetUploadURL(c *gin.Context)
	CreateVideo(c *gin.Context)
	ListVideos(c *gin.Context)
	GetVideo(c *gin.Context)
}

// UploadURLRequest defines the payload for requesting an upload URL
type UploadURLRequest struct {
	Filename    string `json:"filename" binding:"required"`
	ContentType string `json:"content_type" binding:"required"`
	Size        int64  `json:"size" binding:"required"`
}

// CreateVideoRequest defines the payload for creating a video metadata record
type CreateVideoRequest struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	URL         string `json:"url" binding:"required"` // The S3 Key or Full URL
	Size        int64  `json:"size" binding:"required"`
	Duration    int32  `json:"duration"` // Maybe client knows, or we process later
	Format      string `json:"format"`
}
