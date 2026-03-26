package service

import (
	"net/url"
	"strings"
)

func normalizeVideoStatusValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "processing", "pending":
		return "processing"
	case "failed", "error":
		return "failed"
	default:
		return "ready"
	}
}

func normalizeVideoStatusFilter(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.EqualFold(trimmed, "all") {
		return ""
	}
	return normalizeVideoStatusValue(trimmed)
}

func detectStorageType(rawURL string) string {
	if shouldDeleteStoredObject(rawURL) {
		return "S3"
	}
	return "WORKER"
}

func shouldDeleteStoredObject(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return !strings.HasPrefix(trimmed, "/")
	}
	return parsed.Scheme == "" && parsed.Host == "" && !strings.HasPrefix(trimmed, "/")
}

func extractObjectKey(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	return strings.TrimPrefix(parsed.Path, "/")
}
