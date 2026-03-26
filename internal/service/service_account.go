package service

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
	appv1 "stream.api/internal/api/proto/app/v1"
)

func (s *accountAppService) GetMe(ctx context.Context, _ *appv1.GetMeRequest) (*appv1.GetMeResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := buildUserPayload(ctx, s.preferenceRepository, s.billingRepository, result.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.GetMeResponse{User: toProtoUser(payload)}, nil
}
func (s *accountAppService) GetUserById(ctx context.Context, req *wrapperspb.StringValue) (*appv1.User, error) {
	_, err := s.authenticator.RequireTrustedMetadata(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.userRepository.GetByID(ctx, req.Value)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Unauthorized")
	}
	payload, err := buildUserPayload(ctx, s.preferenceRepository, s.billingRepository, user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return toProtoUser(payload), nil
}
func (s *accountAppService) UpdateMe(ctx context.Context, req *appv1.UpdateMeRequest) (*appv1.UpdateMeResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	updatedUser, err := updateUserProfile(ctx, s.userRepository, s.preferenceRepository, s.logger, result.UserID, updateProfileInput{
		Username: req.Username,
		Email:    req.Email,
		Language: req.Language,
		Locale:   req.Locale,
	})
	if err != nil {
		switch {
		case errors.Is(err, errEmailRequired), errors.Is(err, errEmailAlreadyRegistered):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Error(codes.Internal, "Failed to update profile")
		}
	}

	payload, err := buildUserPayload(ctx, s.preferenceRepository, s.billingRepository, updatedUser)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.UpdateMeResponse{User: toProtoUser(payload)}, nil
}
func (s *accountAppService) DeleteMe(ctx context.Context, _ *appv1.DeleteMeRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	userID := result.UserID
	if err := s.accountRepository.DeleteUserAccount(ctx, userID); err != nil {
		s.logger.Error("Failed to delete user", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete account")
	}

	return messageResponse("Account deleted successfully"), nil
}
func (s *accountAppService) ClearMyData(ctx context.Context, _ *appv1.ClearMyDataRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	userID := result.UserID
	if err := s.accountRepository.ClearUserData(ctx, userID); err != nil {
		s.logger.Error("Failed to clear user data", "error", err)
		return nil, status.Error(codes.Internal, "Failed to clear data")
	}

	return messageResponse("Data cleared successfully"), nil
}
func (s *accountAppService) GetPreferences(ctx context.Context, _ *appv1.GetPreferencesRequest) (*appv1.GetPreferencesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	pref, err := loadUserPreferences(ctx, s.preferenceRepository, result.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load preferences")
	}
	return &appv1.GetPreferencesResponse{Preferences: toProtoPreferences(pref)}, nil
}
func (s *accountAppService) UpdatePreferences(ctx context.Context, req *appv1.UpdatePreferencesRequest) (*appv1.UpdatePreferencesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	pref, err := updateUserPreferences(ctx, s.preferenceRepository, s.logger, result.UserID, updatePreferencesInput{
		EmailNotifications:     req.EmailNotifications,
		PushNotifications:      req.PushNotifications,
		MarketingNotifications: req.MarketingNotifications,
		TelegramNotifications:  req.TelegramNotifications,
		Language:               req.Language,
		Locale:                 req.Locale,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save preferences")
	}
	return &appv1.UpdatePreferencesResponse{Preferences: toProtoPreferences(pref)}, nil
}
func (s *accountAppService) GetUsage(ctx context.Context, _ *appv1.GetUsageRequest) (*appv1.GetUsageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := loadUsage(ctx, s.videoRepository, s.logger, result.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load usage")
	}
	return &appv1.GetUsageResponse{
		UserId:       payload.UserID,
		TotalVideos:  payload.TotalVideos,
		TotalStorage: payload.TotalStorage,
	}, nil
}
