package plans

import "stream.api/internal/database/model"

type PlanView struct {
	Plan *model.Plan
}

type ListPlansResult struct {
	Items []PlanView
}

type AdminPlanView struct {
	ID                string
	Name              string
	Description       *string
	Features          []string
	Price             float64
	Cycle             string
	StorageLimit      int64
	UploadLimit       int32
	DurationLimit     int32
	QualityLimit      string
	IsActive          bool
	UserCount         int64
	PaymentCount      int64
	SubscriptionCount int64
}

type ListAdminPlansResult struct {
	Items []AdminPlanView
}

type CreateAdminPlanCommand struct {
	Name         string
	Description  *string
	Features     []string
	Price        float64
	Cycle        string
	StorageLimit int64
	UploadLimit  int32
	IsActive     bool
}

type UpdateAdminPlanCommand struct {
	ID           string
	Name         string
	Description  *string
	Features     []string
	Price        float64
	Cycle        string
	StorageLimit int64
	UploadLimit  int32
	IsActive     bool
}

type DeleteAdminPlanCommand struct {
	ID string
}

type DeleteAdminPlanResult struct {
	Message string
	Mode    string
}
