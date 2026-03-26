package admin

import (
	"context"

	appv1 "stream.api/internal/gen/proto/app/v1"
	adtemplatesmodule "stream.api/internal/modules/adtemplates"
	dashboardmodule "stream.api/internal/modules/dashboard"
	jobsmodule "stream.api/internal/modules/jobs"
	paymentsmodule "stream.api/internal/modules/payments"
	playerconfigsmodule "stream.api/internal/modules/playerconfigs"
	plansmodule "stream.api/internal/modules/plans"
	usersmodule "stream.api/internal/modules/users"
	videosmodule "stream.api/internal/modules/videos"
)

type Handler struct {
	appv1.UnimplementedAdminServiceServer
	dashboard     *dashboardmodule.Module
	users         *usersmodule.Module
	videos        *videosmodule.Module
	payments      *paymentsmodule.Module
	plans         *plansmodule.Module
	adtemplates   *adtemplatesmodule.Module
	playerconfigs *playerconfigsmodule.Module
	jobs          *jobsmodule.Module
}

var _ appv1.AdminServiceServer = (*Handler)(nil)

func NewHandler(dashboard *dashboardmodule.Module, users *usersmodule.Module, videos *videosmodule.Module, payments *paymentsmodule.Module, plans *plansmodule.Module, adtemplates *adtemplatesmodule.Module, playerconfigs *playerconfigsmodule.Module, jobs *jobsmodule.Module) *Handler {
	return &Handler{dashboard: dashboard, users: users, videos: videos, payments: payments, plans: plans, adtemplates: adtemplates, playerconfigs: playerconfigs, jobs: jobs}
}

func (h *Handler) GetAdminDashboard(ctx context.Context, req *appv1.GetAdminDashboardRequest) (*appv1.GetAdminDashboardResponse, error) {
	return h.dashboard.GetAdminDashboard(ctx, req)
}

func (h *Handler) ListAdminUsers(ctx context.Context, req *appv1.ListAdminUsersRequest) (*appv1.ListAdminUsersResponse, error) {
	payload, err := h.users.ListAdminUsers(ctx, usersmodule.ListAdminUsersQuery{Page: req.GetPage(), Limit: req.GetLimit(), Search: req.GetSearch(), Role: req.GetRole()})
	if err != nil { return nil, err }
	items := make([]*appv1.AdminUser, 0, len(payload.Items))
	for _, item := range payload.Items { items = append(items, usersmodule.presentAdminUser(item)) }
	return &appv1.ListAdminUsersResponse{Users: items, Total: payload.Total, Page: payload.Page, Limit: payload.Limit}, nil
}

func (h *Handler) GetAdminUser(ctx context.Context, req *appv1.GetAdminUserRequest) (*appv1.GetAdminUserResponse, error) {
	payload, err := h.users.GetAdminUser(ctx, usersmodule.GetAdminUserQuery{ID: req.GetId()})
	if err != nil { return nil, err }
	return &appv1.GetAdminUserResponse{User: usersmodule.presentAdminUserDetail(*payload)}, nil
}

func (h *Handler) CreateAdminUser(ctx context.Context, req *appv1.CreateAdminUserRequest) (*appv1.CreateAdminUserResponse, error) {
	payload, err := h.users.CreateAdminUser(ctx, usersmodule.CreateAdminUserCommand{Email: req.GetEmail(), Password: req.GetPassword(), Username: req.Username, Role: req.GetRole(), PlanID: common.NullableTrimmedString(req.PlanId)})
	if err != nil { return nil, err }
	return &appv1.CreateAdminUserResponse{User: usersmodule.presentAdminUser(*payload)}, nil
}

func (h *Handler) UpdateAdminUser(ctx context.Context, req *appv1.UpdateAdminUserRequest) (*appv1.UpdateAdminUserResponse, error) {
	var planValue **string
	if req.PlanId != nil {
		plan := common.NullableTrimmedString(req.PlanId)
		planValue = &plan
	}
	payload, err := h.users.UpdateAdminUser(ctx, usersmodule.UpdateAdminUserCommand{ID: req.GetId(), Patch: usersmodule.UserPatch{Email: req.Email, Username: req.Username, Role: req.Role, PlanID: planValue, Password: req.Password}})
	if err != nil { return nil, err }
	return &appv1.UpdateAdminUserResponse{User: usersmodule.presentAdminUser(*payload)}, nil
}

func (h *Handler) UpdateAdminUserReferralSettings(ctx context.Context, req *appv1.UpdateAdminUserReferralSettingsRequest) (*appv1.UpdateAdminUserReferralSettingsResponse, error) {
	payload, err := h.users.UpdateAdminUserReferralSettings(ctx, usersmodule.UpdateReferralSettingsCommand{ID: req.GetId(), RefUsername: req.RefUsername, ClearReferrer: req.ClearReferrer, ReferralEligible: req.ReferralEligible, ReferralRewardBps: req.ReferralRewardBps, ClearReferralRewardBps: req.ClearReferralRewardBps})
	if err != nil { return nil, err }
	return &appv1.UpdateAdminUserReferralSettingsResponse{User: usersmodule.presentAdminUserDetail(*payload)}, nil
}

func (h *Handler) UpdateAdminUserRole(ctx context.Context, req *appv1.UpdateAdminUserRoleRequest) (*appv1.UpdateAdminUserRoleResponse, error) {
	role, err := h.users.UpdateAdminUserRole(ctx, usersmodule.UpdateUserRoleCommand{ID: req.GetId(), Role: req.GetRole()})
	if err != nil { return nil, err }
	return &appv1.UpdateAdminUserRoleResponse{Message: "Role updated", Role: role}, nil
}

func (h *Handler) DeleteAdminUser(ctx context.Context, req *appv1.DeleteAdminUserRequest) (*appv1.MessageResponse, error) {
	if err := h.users.DeleteAdminUser(ctx, usersmodule.DeleteAdminUserCommand{ID: req.GetId()}); err != nil { return nil, err }
	return &appv1.MessageResponse{Message: "User deleted"}, nil
}

func (h *Handler) ListAdminVideos(ctx context.Context, req *appv1.ListAdminVideosRequest) (*appv1.ListAdminVideosResponse, error) {
	return videosmodule.NewHandler(h.videos).ListAdminVideos(ctx, req)
}

func (h *Handler) GetAdminVideo(ctx context.Context, req *appv1.GetAdminVideoRequest) (*appv1.GetAdminVideoResponse, error) {
	return videosmodule.NewHandler(h.videos).GetAdminVideo(ctx, req)
}

func (h *Handler) CreateAdminVideo(ctx context.Context, req *appv1.CreateAdminVideoRequest) (*appv1.CreateAdminVideoResponse, error) {
	return videosmodule.NewHandler(h.videos).CreateAdminVideo(ctx, req)
}

func (h *Handler) UpdateAdminVideo(ctx context.Context, req *appv1.UpdateAdminVideoRequest) (*appv1.UpdateAdminVideoResponse, error) {
	return videosmodule.NewHandler(h.videos).UpdateAdminVideo(ctx, req)
}

func (h *Handler) DeleteAdminVideo(ctx context.Context, req *appv1.DeleteAdminVideoRequest) (*appv1.MessageResponse, error) {
	return videosmodule.NewHandler(h.videos).DeleteAdminVideo(ctx, req)
}

func (h *Handler) ListAdminPayments(ctx context.Context, req *appv1.ListAdminPaymentsRequest) (*appv1.ListAdminPaymentsResponse, error) {
	return paymentsmodule.NewHandler(h.payments).ListAdminPayments(ctx, req)
}

func (h *Handler) GetAdminPayment(ctx context.Context, req *appv1.GetAdminPaymentRequest) (*appv1.GetAdminPaymentResponse, error) {
	return paymentsmodule.NewHandler(h.payments).GetAdminPayment(ctx, req)
}

func (h *Handler) CreateAdminPayment(ctx context.Context, req *appv1.CreateAdminPaymentRequest) (*appv1.CreateAdminPaymentResponse, error) {
	return paymentsmodule.NewHandler(h.payments).CreateAdminPayment(ctx, req)
}

func (h *Handler) UpdateAdminPayment(ctx context.Context, req *appv1.UpdateAdminPaymentRequest) (*appv1.UpdateAdminPaymentResponse, error) {
	return paymentsmodule.NewHandler(h.payments).UpdateAdminPayment(ctx, req)
}

func (h *Handler) ListAdminPlans(ctx context.Context, req *appv1.ListAdminPlansRequest) (*appv1.ListAdminPlansResponse, error) {
	return plansmodule.NewHandler(h.plans).ListAdminPlans(ctx, req)
}

func (h *Handler) CreateAdminPlan(ctx context.Context, req *appv1.CreateAdminPlanRequest) (*appv1.CreateAdminPlanResponse, error) {
	return plansmodule.NewHandler(h.plans).CreateAdminPlan(ctx, req)
}

func (h *Handler) UpdateAdminPlan(ctx context.Context, req *appv1.UpdateAdminPlanRequest) (*appv1.UpdateAdminPlanResponse, error) {
	return plansmodule.NewHandler(h.plans).UpdateAdminPlan(ctx, req)
}

func (h *Handler) DeleteAdminPlan(ctx context.Context, req *appv1.DeleteAdminPlanRequest) (*appv1.DeleteAdminPlanResponse, error) {
	return plansmodule.NewHandler(h.plans).DeleteAdminPlan(ctx, req)
}

func (h *Handler) ListAdminAdTemplates(ctx context.Context, req *appv1.ListAdminAdTemplatesRequest) (*appv1.ListAdminAdTemplatesResponse, error) {
	return adtemplatesmodule.NewHandler(h.adtemplates).ListAdminAdTemplates(ctx, req)
}

func (h *Handler) GetAdminAdTemplate(ctx context.Context, req *appv1.GetAdminAdTemplateRequest) (*appv1.GetAdminAdTemplateResponse, error) {
	return adtemplatesmodule.NewHandler(h.adtemplates).GetAdminAdTemplate(ctx, req)
}

func (h *Handler) CreateAdminAdTemplate(ctx context.Context, req *appv1.CreateAdminAdTemplateRequest) (*appv1.CreateAdminAdTemplateResponse, error) {
	return adtemplatesmodule.NewHandler(h.adtemplates).CreateAdminAdTemplate(ctx, req)
}

func (h *Handler) UpdateAdminAdTemplate(ctx context.Context, req *appv1.UpdateAdminAdTemplateRequest) (*appv1.UpdateAdminAdTemplateResponse, error) {
	return adtemplatesmodule.NewHandler(h.adtemplates).UpdateAdminAdTemplate(ctx, req)
}

func (h *Handler) DeleteAdminAdTemplate(ctx context.Context, req *appv1.DeleteAdminAdTemplateRequest) (*appv1.MessageResponse, error) {
	return adtemplatesmodule.NewHandler(h.adtemplates).DeleteAdminAdTemplate(ctx, req)
}

func (h *Handler) ListAdminPlayerConfigs(ctx context.Context, req *appv1.ListAdminPlayerConfigsRequest) (*appv1.ListAdminPlayerConfigsResponse, error) {
	return playerconfigsmodule.NewHandler(h.playerconfigs).ListAdminPlayerConfigs(ctx, req)
}

func (h *Handler) GetAdminPlayerConfig(ctx context.Context, req *appv1.GetAdminPlayerConfigRequest) (*appv1.GetAdminPlayerConfigResponse, error) {
	return playerconfigsmodule.NewHandler(h.playerconfigs).GetAdminPlayerConfig(ctx, req)
}

func (h *Handler) CreateAdminPlayerConfig(ctx context.Context, req *appv1.CreateAdminPlayerConfigRequest) (*appv1.CreateAdminPlayerConfigResponse, error) {
	return playerconfigsmodule.NewHandler(h.playerconfigs).CreateAdminPlayerConfig(ctx, req)
}

func (h *Handler) UpdateAdminPlayerConfig(ctx context.Context, req *appv1.UpdateAdminPlayerConfigRequest) (*appv1.UpdateAdminPlayerConfigResponse, error) {
	return playerconfigsmodule.NewHandler(h.playerconfigs).UpdateAdminPlayerConfig(ctx, req)
}

func (h *Handler) DeleteAdminPlayerConfig(ctx context.Context, req *appv1.DeleteAdminPlayerConfigRequest) (*appv1.MessageResponse, error) {
	return playerconfigsmodule.NewHandler(h.playerconfigs).DeleteAdminPlayerConfig(ctx, req)
}

func (h *Handler) ListAdminJobs(ctx context.Context, req *appv1.ListAdminJobsRequest) (*appv1.ListAdminJobsResponse, error) {
	return jobsmodule.NewHandler(h.jobs).ListAdminJobs(ctx, req)
}

func (h *Handler) GetAdminJob(ctx context.Context, req *appv1.GetAdminJobRequest) (*appv1.GetAdminJobResponse, error) {
	return jobsmodule.NewHandler(h.jobs).GetAdminJob(ctx, req)
}

func (h *Handler) GetAdminJobLogs(ctx context.Context, req *appv1.GetAdminJobLogsRequest) (*appv1.GetAdminJobLogsResponse, error) {
	return jobsmodule.NewHandler(h.jobs).GetAdminJobLogs(ctx, req)
}

func (h *Handler) CreateAdminJob(ctx context.Context, req *appv1.CreateAdminJobRequest) (*appv1.CreateAdminJobResponse, error) {
	return jobsmodule.NewHandler(h.jobs).CreateAdminJob(ctx, req)
}

func (h *Handler) CancelAdminJob(ctx context.Context, req *appv1.CancelAdminJobRequest) (*appv1.CancelAdminJobResponse, error) {
	return jobsmodule.NewHandler(h.jobs).CancelAdminJob(ctx, req)
}

func (h *Handler) RetryAdminJob(ctx context.Context, req *appv1.RetryAdminJobRequest) (*appv1.RetryAdminJobResponse, error) {
	return jobsmodule.NewHandler(h.jobs).RetryAdminJob(ctx, req)
}

func (h *Handler) ListAdminAgents(ctx context.Context, req *appv1.ListAdminAgentsRequest) (*appv1.ListAdminAgentsResponse, error) {
	return jobsmodule.NewHandler(h.jobs).ListAdminAgents(ctx, req)
}

func (h *Handler) RestartAdminAgent(ctx context.Context, req *appv1.RestartAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	return jobsmodule.NewHandler(h.jobs).RestartAdminAgent(ctx, req)
}

func (h *Handler) UpdateAdminAgent(ctx context.Context, req *appv1.UpdateAdminAgentRequest) (*appv1.AdminAgentCommandResponse, error) {
	return jobsmodule.NewHandler(h.jobs).UpdateAdminAgent(ctx, req)
}
