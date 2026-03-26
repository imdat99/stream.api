package domains

import "stream.api/internal/database/model"

type ListDomainsQuery struct {
	UserID string
}

type CreateDomainCommand struct {
	UserID string
	Name   string
}

type DeleteDomainCommand struct {
	UserID string
	ID     string
}

type DomainView struct {
	Domain *model.Domain
}

type ListDomainsResult struct {
	Items []DomainView
}
