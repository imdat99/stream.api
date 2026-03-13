package usage

type UsagePayload struct {
	UserID       string `json:"user_id"`
	TotalVideos  int64  `json:"total_videos"`
	TotalStorage int64  `json:"total_storage"`
}
