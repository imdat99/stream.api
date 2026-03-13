//go:build ignore
// +build ignore

package admin

import (
	"fmt"
	"strings"
	"time"
)

func adminFormatTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func adminFormatTimeValue(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func adminStringPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func adminStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func adminInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	return value
}

func adminStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func adminStringSliceValue(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	return append([]string(nil), values...)
}

func adminBoolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func adminInvoiceID(id string) string {
	trimmed := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	return "INV-" + strings.ToUpper(trimmed)
}

func adminTransactionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}
