package jobs

import videodomain "stream.api/internal/video"

type ListAdminJobsQuery struct {
	AgentID            string
	Offset             int
	Limit              int
	Cursor             *string
	PageSize           int
	UseCursorPagination bool
}

type ListAdminJobsResult struct {
	Jobs       []*videodomain.Job
	Total      int64
	Offset     int
	Limit      int
	HasMore    bool
	PageSize   int
	NextCursor *string
}

type GetAdminJobQuery struct {
	ID string
}

type CreateAdminJobCommand struct {
	Command   string
	Image     string
	Name      string
	UserID    string
	VideoID   *string
	Env       map[string]string
	Priority  int
	TimeLimit int64
}

type CancelAdminJobCommand struct {
	ID string
}

type CancelAdminJobResult struct {
	Status string
	JobID  string
}

type RetryAdminJobCommand struct {
	ID string
}

type AgentCommand struct {
	ID      string
	Command string
	Success string
}
