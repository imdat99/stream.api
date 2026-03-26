package service

import (
	"crypto/rand"
	"encoding/base64"
)

func generateOAuthState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func googleOAuthStateCacheKey(state string) string {
	return "google_oauth_state:" + state
}
