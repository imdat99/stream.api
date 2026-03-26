package playerconfigs

import "stream.api/internal/database/model"

type PlayerConfigView struct {
	Config *model.PlayerConfig
}

type ListPlayerConfigsQuery struct {
	UserID string
}

type ListPlayerConfigsResult struct {
	Items []PlayerConfigView
}

type CreatePlayerConfigCommand struct {
	UserID        string
	Name          string
	Description   *string
	Autoplay      bool
	Loop          bool
	Muted         bool
	ShowControls  bool
	Pip           bool
	Airplay       bool
	Chromecast    bool
	IsActive      *bool
	IsDefault     *bool
	EncrytionM3U8 *bool
	LogoURL       *string
}

type UpdatePlayerConfigCommand struct {
	UserID        string
	ID            string
	Name          string
	Description   *string
	Autoplay      bool
	Loop          bool
	Muted         bool
	ShowControls  bool
	Pip           bool
	Airplay       bool
	Chromecast    bool
	IsActive      *bool
	IsDefault     *bool
	EncrytionM3U8 *bool
	LogoURL       *string
}

type DeletePlayerConfigCommand struct {
	UserID string
	ID     string
}

type AdminPlayerConfigView struct {
	ID            string
	UserID        string
	Name          string
	Description   *string
	Autoplay      bool
	Loop          bool
	Muted         bool
	ShowControls  bool
	Pip           bool
	Airplay       bool
	Chromecast    bool
	IsActive      bool
	IsDefault     bool
	OwnerEmail    *string
	CreatedAt     *string
	UpdatedAt     *string
	EncrytionM3U8 bool
	LogoURL       *string
}

type ListAdminPlayerConfigsQuery struct {
	Page   int32
	Limit  int32
	Search *string
	UserID *string
}

type ListAdminPlayerConfigsResult struct {
	Items []AdminPlayerConfigView
	Total int64
	Page  int32
	Limit int32
}

type GetAdminPlayerConfigQuery struct {
	ID string
}

type CreateAdminPlayerConfigCommand struct {
	UserID        string
	Name          string
	Description   *string
	Autoplay      bool
	Loop          bool
	Muted         bool
	ShowControls  bool
	Pip           bool
	Airplay       bool
	Chromecast    bool
	IsActive      bool
	IsDefault     bool
	EncrytionM3U8 *bool
	LogoURL       *string
}

type UpdateAdminPlayerConfigCommand struct {
	ID            string
	UserID        string
	Name          string
	Description   *string
	Autoplay      bool
	Loop          bool
	Muted         bool
	ShowControls  bool
	Pip           bool
	Airplay       bool
	Chromecast    bool
	IsActive      bool
	IsDefault     bool
	EncrytionM3U8 *bool
	LogoURL       *string
}

type DeleteAdminPlayerConfigCommand struct {
	ID string
}
