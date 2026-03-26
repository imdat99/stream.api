package adtemplates

import "stream.api/internal/database/model"

type AdTemplateView struct {
	Template *model.AdTemplate
}

type ListAdTemplatesQuery struct {
	UserID string
}

type ListAdTemplatesResult struct {
	Items []AdTemplateView
}

type CreateAdTemplateCommand struct {
	UserID      string
	Name        string
	Description *string
	VastTagURL  string
	AdFormat    string
	Duration    *int32
	IsActive    *bool
	IsDefault   *bool
}

type UpdateAdTemplateCommand struct {
	UserID      string
	ID          string
	Name        string
	Description *string
	VastTagURL  string
	AdFormat    string
	Duration    *int32
	IsActive    *bool
	IsDefault   *bool
}

type DeleteAdTemplateCommand struct {
	UserID string
	ID     string
}

type AdminAdTemplateView struct {
	ID          string
	UserID      string
	Name        string
	Description *string
	VastTagURL  string
	AdFormat    string
	Duration    *int64
	IsActive    bool
	IsDefault   bool
	OwnerEmail  *string
	CreatedAt   *string
	UpdatedAt   *string
}

type ListAdminAdTemplatesQuery struct {
	Page   int32
	Limit  int32
	Search *string
	UserID *string
}

type ListAdminAdTemplatesResult struct {
	Items []AdminAdTemplateView
	Total int64
	Page  int32
	Limit int32
}

type GetAdminAdTemplateQuery struct {
	ID string
}

type CreateAdminAdTemplateCommand struct {
	UserID      string
	Name        string
	Description *string
	VastTagURL  string
	AdFormat    string
	Duration    *int64
	IsActive    bool
	IsDefault   bool
}

type UpdateAdminAdTemplateCommand struct {
	ID          string
	UserID      string
	Name        string
	Description *string
	VastTagURL  string
	AdFormat    string
	Duration    *int64
	IsActive    bool
	IsDefault   bool
}

type DeleteAdminAdTemplateCommand struct {
	ID string
}
