package payments

import (
	"context"
	"encoding/json"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

type Handler struct {
	appv1.UnimplementedPaymentsServiceServer
	module *Module
}

var _ appv1.PaymentsServiceServer = (*Handler)(nil)

func NewHandler(module *Module) *Handler { return &Handler{module: module} }

func (h *Handler) CreatePayment(ctx context.Context, req *appv1.CreatePaymentRequest) (*appv1.CreatePaymentResponse, error) {
	authResult, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	planID := strings.TrimSpace(req.GetPlanId())
	if planID == "" {
		return nil, status.Error(codes.InvalidArgument, "Plan ID is required")
	}
	if !common.IsAllowedTermMonths(req.GetTermMonths()) {
		return nil, status.Error(codes.InvalidArgument, "Term months must be one of 1, 3, 6, or 12")
	}
	paymentMethod := common.NormalizePaymentMethod(req.GetPaymentMethod())
	if paymentMethod == "" {
		return nil, status.Error(codes.InvalidArgument, "Payment method must be wallet or topup")
	}
	result, err := h.module.CreatePayment(ctx, CreatePaymentCommand{UserID: authResult.UserID, PlanID: planID, TermMonths: req.GetTermMonths(), PaymentMethod: paymentMethod, TopupAmount: req.TopupAmount})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to create payment")
	}
	return presentCreatePaymentResponse(result), nil
}

func (h *Handler) ListPaymentHistory(ctx context.Context, req *appv1.ListPaymentHistoryRequest) (*appv1.ListPaymentHistoryResponse, error) {
	authResult, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	result, err := h.module.ListPaymentHistory(ctx, PaymentHistoryQuery{UserID: authResult.UserID, Page: req.GetPage(), Limit: req.GetLimit()})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to fetch payment history")
	}
	return presentPaymentHistoryResponse(result), nil
}

func (h *Handler) TopupWallet(ctx context.Context, req *appv1.TopupWalletRequest) (*appv1.TopupWalletResponse, error) {
	authResult, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	result, err := h.module.TopupWallet(ctx, TopupWalletCommand{UserID: authResult.UserID, Amount: req.GetAmount()})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to top up wallet")
	}
	return presentTopupWalletResponse(result), nil
}

func (h *Handler) DownloadInvoice(ctx context.Context, req *appv1.DownloadInvoiceRequest) (*appv1.DownloadInvoiceResponse, error) {
	authResult, err := h.module.runtime.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	result, err := h.module.DownloadInvoice(ctx, DownloadInvoiceQuery{UserID: authResult.UserID, ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to download invoice")
	}
	return presentDownloadInvoiceResponse(result), nil
}

func (h *Handler) ListAdminPayments(ctx context.Context, req *appv1.ListAdminPaymentsRequest) (*appv1.ListAdminPaymentsResponse, error) {
	result, err := h.module.ListAdminPayments(ctx, ListAdminPaymentsQuery{Page: req.GetPage(), Limit: req.GetLimit(), UserID: strings.TrimSpace(req.GetUserId()), StatusFilter: strings.TrimSpace(req.GetStatus())})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to list payments")
	}
	return presentListAdminPaymentsResponse(result), nil
}

func (h *Handler) GetAdminPayment(ctx context.Context, req *appv1.GetAdminPaymentRequest) (*appv1.GetAdminPaymentResponse, error) {
	result, err := h.module.GetAdminPayment(ctx, GetAdminPaymentQuery{ID: strings.TrimSpace(req.GetId())})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to get payment")
	}
	return presentGetAdminPaymentResponse(*result), nil
}

func (h *Handler) CreateAdminPayment(ctx context.Context, req *appv1.CreateAdminPaymentRequest) (*appv1.CreateAdminPaymentResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	planID := strings.TrimSpace(req.GetPlanId())
	if userID == "" || planID == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID and plan ID are required")
	}
	if !common.IsAllowedTermMonths(req.GetTermMonths()) {
		return nil, status.Error(codes.InvalidArgument, "Term months must be one of 1, 3, 6, or 12")
	}
	paymentMethod := common.NormalizePaymentMethod(req.GetPaymentMethod())
	if paymentMethod == "" {
		return nil, status.Error(codes.InvalidArgument, "Payment method must be wallet or topup")
	}
	result, err := h.module.CreateAdminPayment(ctx, CreateAdminPaymentCommand{UserID: userID, PlanID: planID, TermMonths: req.GetTermMonths(), PaymentMethod: paymentMethod, TopupAmount: req.TopupAmount})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to create payment")
	}
	return presentCreateAdminPaymentResponse(result), nil
}

func (h *Handler) UpdateAdminPayment(ctx context.Context, req *appv1.UpdateAdminPaymentRequest) (*appv1.UpdateAdminPaymentResponse, error) {
	result, err := h.module.UpdateAdminPayment(ctx, UpdateAdminPaymentCommand{ID: strings.TrimSpace(req.GetId()), NewStatus: req.GetStatus()})
	if err != nil {
		return nil, h.handleError(ctx, err, "Failed to update payment")
	}
	return presentUpdateAdminPaymentResponse(*result), nil
}

func (h *Handler) handleError(ctx context.Context, err error, fallback string) error {
	if err == nil {
		return nil
	}
	if validationErr, ok := err.(*PaymentValidationError); ok {
		body := validationErr.apiBody()
		if encoded, marshalErr := json.Marshal(body); marshalErr == nil {
			_ = grpc.SetTrailer(ctx, metadata.Pairs("x-error-body", string(encoded)))
		}
		return status.Error(codes.Code(validationErr.GRPCCode), validationErr.Message)
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	h.module.runtime.Logger().Error(fallback, "error", err)
	return status.Error(codes.Internal, fallback)
}
