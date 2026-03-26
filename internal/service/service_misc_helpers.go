package service

import (
	"context"

	"stream.api/internal/middleware"
)

func (s *appServices) authenticate(ctx context.Context) (*middleware.AuthResult, error) {
	return s.authenticator.Authenticate(ctx)
}
