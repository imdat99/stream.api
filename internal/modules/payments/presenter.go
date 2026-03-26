package payments

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	appv1 "stream.api/internal/gen/proto/app/v1"
	"stream.api/internal/modules/common"
)

func presentCreatePaymentResponse(result *CreatePaymentResult) *appv1.CreatePaymentResponse {
	return &appv1.CreatePaymentResponse{
		Payment:       common.ToProtoPayment(result.Payment),
		Subscription:  common.ToProtoPlanSubscription(result.Subscription),
		WalletBalance: result.WalletBalance,
		InvoiceId:     result.InvoiceID,
		Message:       result.Message,
	}
}

func presentPaymentHistoryResponse(result *PaymentHistoryResult) *appv1.ListPaymentHistoryResponse {
	items := make([]*appv1.PaymentHistoryItem, 0, len(result.Items))
	for _, row := range result.Items {
		items = append(items, &appv1.PaymentHistoryItem{
			Id:            row.ID,
			Amount:        row.Amount,
			Currency:      row.Currency,
			Status:        row.Status,
			PlanId:        row.PlanID,
			PlanName:      row.PlanName,
			InvoiceId:     row.InvoiceID,
			Kind:          row.Kind,
			TermMonths:    row.TermMonths,
			PaymentMethod: row.PaymentMethod,
			ExpiresAt:     parseRFC3339ToProto(row.ExpiresAt),
			CreatedAt:     parseRFC3339ToProto(row.CreatedAt),
		})
	}
	return &appv1.ListPaymentHistoryResponse{
		Payments: items,
		Total:    result.Total,
		Page:     result.Page,
		Limit:    result.Limit,
		HasPrev:  result.HasPrev,
		HasNext:  result.HasNext,
	}
}

func presentTopupWalletResponse(result *TopupWalletResult) *appv1.TopupWalletResponse {
	return &appv1.TopupWalletResponse{
		WalletTransaction: common.ToProtoWalletTransaction(result.WalletTransaction),
		WalletBalance:     result.WalletBalance,
		InvoiceId:         result.InvoiceID,
	}
}

func presentDownloadInvoiceResponse(result *DownloadInvoiceResult) *appv1.DownloadInvoiceResponse {
	return &appv1.DownloadInvoiceResponse{
		Filename:    result.Filename,
		ContentType: result.ContentType,
		Content:     result.Content,
	}
}

func presentAdminPayment(view AdminPaymentView) *appv1.AdminPayment {
	return &appv1.AdminPayment{
		Id:            view.ID,
		UserId:        view.UserID,
		PlanId:        view.PlanID,
		Amount:        view.Amount,
		Currency:      view.Currency,
		Status:        view.Status,
		Provider:      view.Provider,
		TransactionId: view.TransactionID,
		InvoiceId:     view.InvoiceID,
		CreatedAt:     parseRFC3339ToProto(view.CreatedAt),
		UpdatedAt:     parseRFC3339ToProto(view.UpdatedAt),
		UserEmail:     view.UserEmail,
		PlanName:      view.PlanName,
		TermMonths:    view.TermMonths,
		PaymentMethod: view.PaymentMethod,
		ExpiresAt:     view.ExpiresAt,
		WalletAmount:  view.WalletAmount,
		TopupAmount:   view.TopupAmount,
	}
}

func presentListAdminPaymentsResponse(result *ListAdminPaymentsResult) *appv1.ListAdminPaymentsResponse {
	items := make([]*appv1.AdminPayment, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, presentAdminPayment(item))
	}
	return &appv1.ListAdminPaymentsResponse{Payments: items, Total: result.Total, Page: result.Page, Limit: result.Limit}
}

func presentGetAdminPaymentResponse(view AdminPaymentView) *appv1.GetAdminPaymentResponse {
	return &appv1.GetAdminPaymentResponse{Payment: presentAdminPayment(view)}
}

func presentCreateAdminPaymentResponse(result *CreateAdminPaymentResult) *appv1.CreateAdminPaymentResponse {
	return &appv1.CreateAdminPaymentResponse{
		Payment:       presentAdminPayment(result.Payment),
		Subscription:  common.ToProtoPlanSubscription(result.Subscription),
		WalletBalance: result.WalletBalance,
		InvoiceId:     result.InvoiceID,
	}
}

func presentUpdateAdminPaymentResponse(view AdminPaymentView) *appv1.UpdateAdminPaymentResponse {
	return &appv1.UpdateAdminPaymentResponse{Payment: presentAdminPayment(view)}
}

func parseRFC3339ToProto(value *string) *timestamppb.Timestamp {
	if value == nil || *value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return nil
	}
	return timestamppb.New(parsed.UTC())
}
