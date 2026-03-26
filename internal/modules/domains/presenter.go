package domains

import (
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

func presentListDomainsResponse(result *ListDomainsResult) *appv1.ListDomainsResponse {
	items := make([]*appv1.Domain, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, common.ToProtoDomain(item.Domain))
	}
	return &appv1.ListDomainsResponse{Domains: items}
}

func presentCreateDomainResponse(view DomainView) *appv1.CreateDomainResponse {
	return &appv1.CreateDomainResponse{Domain: common.ToProtoDomain(view.Domain)}
}
