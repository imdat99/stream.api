package service

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
)

func toProtoPayment(item *model.Payment) *appv1.Payment {
	if item == nil {
		return nil
	}
	return &appv1.Payment{
		Id:            item.ID,
		UserId:        item.UserID,
		PlanId:        item.PlanID,
		Amount:        item.Amount,
		Currency:      normalizeCurrency(item.Currency),
		Status:        normalizePaymentStatus(item.Status),
		Provider:      strings.ToUpper(stringValue(item.Provider)),
		TransactionId: item.TransactionID,
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timestamppb.New(item.UpdatedAt.UTC()),
	}
}

func toProtoPlanSubscription(item *model.PlanSubscription) *appv1.PlanSubscription {
	if item == nil {
		return nil
	}
	return &appv1.PlanSubscription{
		Id:            item.ID,
		UserId:        item.UserID,
		PaymentId:     item.PaymentID,
		PlanId:        item.PlanID,
		TermMonths:    item.TermMonths,
		PaymentMethod: item.PaymentMethod,
		WalletAmount:  item.WalletAmount,
		TopupAmount:   item.TopupAmount,
		StartedAt:     timestamppb.New(item.StartedAt.UTC()),
		ExpiresAt:     timestamppb.New(item.ExpiresAt.UTC()),
		CreatedAt:     timeToProto(item.CreatedAt),
		UpdatedAt:     timeToProto(item.UpdatedAt),
	}
}

func toProtoWalletTransaction(item *model.WalletTransaction) *appv1.WalletTransaction {
	if item == nil {
		return nil
	}
	return &appv1.WalletTransaction{
		Id:         item.ID,
		UserId:     item.UserID,
		Type:       item.Type,
		Amount:     item.Amount,
		Currency:   normalizeCurrency(item.Currency),
		Note:       item.Note,
		PaymentId:  item.PaymentID,
		PlanId:     item.PlanID,
		TermMonths: item.TermMonths,
		CreatedAt:  timeToProto(item.CreatedAt),
		UpdatedAt:  timeToProto(item.UpdatedAt),
	}
}

func normalizePaymentStatus(status *string) string {
	value := strings.ToLower(strings.TrimSpace(stringValue(status)))
	switch value {
	case "success", "succeeded", "paid":
		return "success"
	case "failed", "error", "canceled", "cancelled":
		return "failed"
	case "pending", "processing":
		return "pending"
	default:
		if value == "" {
			return "success"
		}
		return value
	}
}

func normalizeCurrency(currency *string) string {
	value := strings.ToUpper(strings.TrimSpace(stringValue(currency)))
	if value == "" {
		return "USD"
	}
	return value
}

func normalizePaymentMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case paymentMethodWallet:
		return paymentMethodWallet
	case paymentMethodTopup:
		return paymentMethodTopup
	default:
		return ""
	}
}

func normalizeOptionalPaymentMethod(value *string) *string {
	normalized := normalizePaymentMethod(stringValue(value))
	if normalized == "" {
		return nil
	}
	return &normalized
}

func buildInvoiceID(id string) string {
	trimmed := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	return "INV-" + strings.ToUpper(trimmed)
}

func buildTransactionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func buildInvoiceFilename(id string) string {
	return fmt.Sprintf("invoice-%s.txt", id)
}
