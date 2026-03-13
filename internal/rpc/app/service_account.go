package app

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	authapi "stream.api/internal/api/auth"
	preferencesapi "stream.api/internal/api/preferences"
	usageapi "stream.api/internal/api/usage"
	"stream.api/internal/database/model"
	appv1 "stream.api/internal/gen/proto/app/v1"
)

func (s *appServices) GetMe(ctx context.Context, _ *appv1.GetMeRequest) (*appv1.GetMeResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := authapi.BuildUserPayload(ctx, s.db, result.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.GetMeResponse{User: toProtoUserPayload(payload)}, nil
}
func (s *appServices) UpdateMe(ctx context.Context, req *appv1.UpdateMeRequest) (*appv1.UpdateMeResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	updatedUser, err := authapi.UpdateUserProfile(ctx, s.db, s.logger, result.UserID, authapi.UpdateProfileInput{
		Username: req.Username,
		Email:    req.Email,
		Language: req.Language,
		Locale:   req.Locale,
	})
	if err != nil {
		switch {
		case errors.Is(err, authapi.ErrEmailRequired), errors.Is(err, authapi.ErrEmailAlreadyRegistered):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Error(codes.Internal, "Failed to update profile")
		}
	}

	payload, err := authapi.BuildUserPayload(ctx, s.db, updatedUser)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to build user payload")
	}
	return &appv1.UpdateMeResponse{User: toProtoUser(payload)}, nil
}
func (s *appServices) DeleteMe(ctx context.Context, _ *appv1.DeleteMeRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	userID := result.UserID
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.WalletTransaction{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.PlanSubscription{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.UserPreference{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Payment{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", userID).Delete(&model.User{}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		s.logger.Error("Failed to delete user", "error", err)
		return nil, status.Error(codes.Internal, "Failed to delete account")
	}

	return messageResponse("Account deleted successfully"), nil
}
func (s *appServices) ClearMyData(ctx context.Context, _ *appv1.ClearMyDataRequest) (*appv1.MessageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	userID := result.UserID
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.Notification{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Domain{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AdTemplate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.VideoAdConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{"storage_used": 0}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		s.logger.Error("Failed to clear user data", "error", err)
		return nil, status.Error(codes.Internal, "Failed to clear data")
	}

	return messageResponse("Data cleared successfully"), nil
}
func (s *appServices) GetPreferences(ctx context.Context, _ *appv1.GetPreferencesRequest) (*appv1.GetPreferencesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	pref, err := preferencesapi.LoadUserPreferences(ctx, s.db, result.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load preferences")
	}
	return &appv1.GetPreferencesResponse{Preferences: toProtoPreferences(pref)}, nil
}
func (s *appServices) UpdatePreferences(ctx context.Context, req *appv1.UpdatePreferencesRequest) (*appv1.UpdatePreferencesResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	pref, err := preferencesapi.UpdateUserPreferences(ctx, s.db, s.logger, result.UserID, preferencesapi.UpdateInput{
		EmailNotifications:     req.EmailNotifications,
		PushNotifications:      req.PushNotifications,
		MarketingNotifications: req.MarketingNotifications,
		TelegramNotifications:  req.TelegramNotifications,
		Autoplay:               req.Autoplay,
		Loop:                   req.Loop,
		Muted:                  req.Muted,
		ShowControls:           req.ShowControls,
		Pip:                    req.Pip,
		Airplay:                req.Airplay,
		Chromecast:             req.Chromecast,
		Language:               req.Language,
		Locale:                 req.Locale,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to save preferences")
	}
	return &appv1.UpdatePreferencesResponse{Preferences: toProtoPreferences(pref)}, nil
}
func (s *appServices) GetUsage(ctx context.Context, _ *appv1.GetUsageRequest) (*appv1.GetUsageResponse, error) {
	result, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := usageapi.LoadUsage(ctx, s.db, s.logger, result.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load usage")
	}
	return &appv1.GetUsageResponse{
		UserId:       payload.UserID,
		TotalVideos:  payload.TotalVideos,
		TotalStorage: payload.TotalStorage,
	}, nil
}
