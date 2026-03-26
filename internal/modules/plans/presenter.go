package plans

import appv1 "stream.api/internal/gen/proto/app/v1"

func presentListPlansResponse(result *ListPlansResult) *appv1.ListPlansResponse {
	items := make([]*appv1.Plan, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, &appv1.Plan{
			Id:            item.Plan.ID,
			Name:          item.Plan.Name,
			Description:   item.Plan.Description,
			Price:         item.Plan.Price,
			Cycle:         item.Plan.Cycle,
			StorageLimit:  item.Plan.StorageLimit,
			UploadLimit:   item.Plan.UploadLimit,
			DurationLimit: item.Plan.DurationLimit,
			QualityLimit:  item.Plan.QualityLimit,
			Features:      item.Plan.Features,
			IsActive:      item.Plan.IsActive != nil && *item.Plan.IsActive,
		})
	}
	return &appv1.ListPlansResponse{Plans: items}
}

func presentAdminPlan(view AdminPlanView) *appv1.AdminPlan {
	return &appv1.AdminPlan{
		Id:                view.ID,
		Name:              view.Name,
		Description:       view.Description,
		Features:          view.Features,
		Price:             view.Price,
		Cycle:             view.Cycle,
		StorageLimit:      view.StorageLimit,
		UploadLimit:       view.UploadLimit,
		DurationLimit:     view.DurationLimit,
		QualityLimit:      view.QualityLimit,
		IsActive:          view.IsActive,
		UserCount:         view.UserCount,
		PaymentCount:      view.PaymentCount,
		SubscriptionCount: view.SubscriptionCount,
	}
}

func presentListAdminPlansResponse(result *ListAdminPlansResult) *appv1.ListAdminPlansResponse {
	items := make([]*appv1.AdminPlan, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdminPlan(item))
	}
	return &appv1.ListAdminPlansResponse{Plans: items}
}

func presentCreateAdminPlanResponse(view AdminPlanView) *appv1.CreateAdminPlanResponse {
	return &appv1.CreateAdminPlanResponse{Plan: presentAdminPlan(view)}
}

func presentUpdateAdminPlanResponse(view AdminPlanView) *appv1.UpdateAdminPlanResponse {
	return &appv1.UpdateAdminPlanResponse{Plan: presentAdminPlan(view)}
}

func presentDeleteAdminPlanResponse(result *DeleteAdminPlanResult) *appv1.DeleteAdminPlanResponse {
	return &appv1.DeleteAdminPlanResponse{Message: result.Message, Mode: result.Mode}
}
