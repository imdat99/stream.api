package service

import "strings"

func normalizeDomain(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, "/")
	return normalized
}

func normalizeAdFormat(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "mid-roll", "post-roll":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "pre-roll"
	}
}

func adTemplateIsActive(value *bool) bool {
	return value == nil || *value
}

func playerConfigIsActive(value *bool) bool {
	return value == nil || *value
}
