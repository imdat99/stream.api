package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	appv1 "stream.api/internal/api/proto/app/v1"
	"stream.api/internal/database/model"
	"stream.api/internal/video"
)

func (s *appServices) GetAdminDashboard(ctx context.Context, _ *appv1.GetAdminDashboardRequest) (*appv1.GetAdminDashboardResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	dashboard := &appv1.AdminDashboard{}
	db := s.db.WithContext(ctx)

	db.Model(&model.User{}).Count(&dashboard.TotalUsers)
	db.Model(&model.Video{}).Count(&dashboard.TotalVideos)
	db.Model(&model.User{}).Select("COALESCE(SUM(storage_used), 0)").Row().Scan(&dashboard.TotalStorageUsed)
	db.Model(&model.Payment{}).Count(&dashboard.TotalPayments)
	db.Model(&model.Payment{}).Where("status = ?", "SUCCESS").Select("COALESCE(SUM(amount), 0)").Row().Scan(&dashboard.TotalRevenue)
	db.Model(&model.PlanSubscription{}).Where("expires_at > ?", time.Now()).Count(&dashboard.ActiveSubscriptions)
	db.Model(&model.AdTemplate{}).Count(&dashboard.TotalAdTemplates)

	today := time.Now().Truncate(24 * time.Hour)
	db.Model(&model.User{}).Where("created_at >= ?", today).Count(&dashboard.NewUsersToday)
	db.Model(&model.Video{}).Where("created_at >= ?", today).Count(&dashboard.NewVideosToday)

	return &appv1.GetAdminDashboardResponse{Dashboard: dashboard}, nil
}
func (s *appServices) ListAdminUsers(ctx context.Context, req *appv1.ListAdminUsersRequest) (*appv1.ListAdminUsersResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	limitInt := int(limit)
	search := strings.TrimSpace(req.GetSearch())
	role := strings.TrimSpace(req.GetRole())

	db := s.db.WithContext(ctx).Model(&model.User{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("email ILIKE ? OR username ILIKE ?", like, like)
	}
	if role != "" {
		db = db.Where("UPPER(role) = ?", strings.ToUpper(role))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list users")
	}

	var users []model.User
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&users).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list users")
	}

	items := make([]*appv1.AdminUser, 0, len(users))
	for _, user := range users {
		payload, err := s.buildAdminUser(ctx, &user)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list users")
		}
		items = append(items, payload)
	}

	return &appv1.ListAdminUsersResponse{Users: items, Total: total, Page: page, Limit: limit}, nil
}
func (s *appServices) GetAdminUser(ctx context.Context, req *appv1.GetAdminUserRequest) (*appv1.GetAdminUserResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get user")
	}

	var subscription *model.PlanSubscription
	var subscriptionRecord model.PlanSubscription
	if err := s.db.WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").First(&subscriptionRecord).Error; err == nil {
		subscription = &subscriptionRecord
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.Internal, "Failed to get user")
	}

	detail, err := s.buildAdminUserDetail(ctx, &user, subscription)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get user")
	}
	return &appv1.GetAdminUserResponse{User: detail}, nil
}
func (s *appServices) CreateAdminUser(ctx context.Context, req *appv1.CreateAdminUserRequest) (*appv1.CreateAdminUserResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(req.GetEmail())
	password := req.GetPassword()
	if email == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "Email and password are required")
	}

	role := normalizeAdminRoleValue(req.GetRole())
	if !isValidAdminRoleValue(role) {
		return nil, status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK")
	}

	planID := nullableTrimmedString(req.PlanId)
	if err := s.ensurePlanExists(ctx, planID); err != nil {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to hash password")
	}

	user := &model.User{
		ID:       uuid.New().String(),
		Email:    email,
		Password: model.StringPtr(string(hashedPassword)),
		Username: nullableTrimmedString(req.Username),
		Role:     model.StringPtr(role),
		PlanID:   planID,
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, "Email already registered")
		}
		return nil, status.Error(codes.Internal, "Failed to create user")
	}

	payload, err := s.buildAdminUser(ctx, user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}
	return &appv1.CreateAdminUserResponse{User: payload}, nil
}
func (s *appServices) UpdateAdminUser(ctx context.Context, req *appv1.UpdateAdminUserRequest) (*appv1.UpdateAdminUserResponse, error) {
	adminResult, err := s.requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	updates := map[string]interface{}{}
	if req.Email != nil {
		email := strings.TrimSpace(req.GetEmail())
		if email == "" {
			return nil, status.Error(codes.InvalidArgument, "Email is required")
		}
		updates["email"] = email
	}
	if req.Username != nil {
		updates["username"] = nullableTrimmedString(req.Username)
	}
	if req.Role != nil {
		role := normalizeAdminRoleValue(req.GetRole())
		if !isValidAdminRoleValue(role) {
			return nil, status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK")
		}
		if id == adminResult.UserID && role != "ADMIN" {
			return nil, status.Error(codes.InvalidArgument, "Cannot change your own role")
		}
		updates["role"] = role
	}
	if req.PlanId != nil {
		planID := nullableTrimmedString(req.PlanId)
		if err := s.ensurePlanExists(ctx, planID); err != nil {
			return nil, err
		}
		updates["plan_id"] = planID
	}
	if req.Password != nil {
		if strings.TrimSpace(req.GetPassword()) == "" {
			return nil, status.Error(codes.InvalidArgument, "Password must not be empty")
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to hash password")
		}
		updates["password"] = string(hashedPassword)
	}
	if len(updates) == 0 {
		var user model.User
		if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, status.Error(codes.NotFound, "User not found")
			}
			return nil, status.Error(codes.Internal, "Failed to update user")
		}
		payload, err := s.buildAdminUser(ctx, &user)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to update user")
		}
		return &appv1.UpdateAdminUserResponse{User: payload}, nil
	}

	result := s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, "Email already registered")
		}
		return nil, status.Error(codes.Internal, "Failed to update user")
	}
	if result.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to update user")
	}
	payload, err := s.buildAdminUser(ctx, &user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update user")
	}
	return &appv1.UpdateAdminUserResponse{User: payload}, nil
}
func (s *appServices) UpdateAdminUserReferralSettings(ctx context.Context, req *appv1.UpdateAdminUserReferralSettingsRequest) (*appv1.UpdateAdminUserReferralSettingsResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	if req.ClearReferrer != nil && req.GetClearReferrer() && req.RefUsername != nil && strings.TrimSpace(req.GetRefUsername()) != "" {
		return nil, status.Error(codes.InvalidArgument, "Cannot set and clear referrer at the same time")
	}
	if req.ClearReferralRewardBps != nil && req.GetClearReferralRewardBps() && req.ReferralRewardBps != nil {
		return nil, status.Error(codes.InvalidArgument, "Cannot set and clear referral reward override at the same time")
	}
	if req.ReferralRewardBps != nil {
		bps := req.GetReferralRewardBps()
		if bps < 0 || bps > 10000 {
			return nil, status.Error(codes.InvalidArgument, "Referral reward bps must be between 0 and 10000")
		}
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}

	updates := map[string]any{}
	if req.RefUsername != nil || (req.ClearReferrer != nil && req.GetClearReferrer()) {
		if referralRewardProcessed(&user) {
			return nil, status.Error(codes.InvalidArgument, "Cannot change referrer after reward has been granted")
		}
		if req.ClearReferrer != nil && req.GetClearReferrer() {
			updates["referred_by_user_id"] = nil
		} else if req.RefUsername != nil {
			referrer, err := s.loadReferralUserByUsernameStrict(ctx, req.GetRefUsername())
			if err != nil {
				return nil, err
			}
			if referrer.ID == user.ID {
				return nil, status.Error(codes.InvalidArgument, "User cannot refer themselves")
			}
			updates["referred_by_user_id"] = referrer.ID
		}
	}
	if req.ReferralEligible != nil {
		updates["referral_eligible"] = req.GetReferralEligible()
	}
	if req.ClearReferralRewardBps != nil && req.GetClearReferralRewardBps() {
		updates["referral_reward_bps"] = nil
	} else if req.ReferralRewardBps != nil {
		updates["referral_reward_bps"] = req.GetReferralRewardBps()
	}

	if len(updates) > 0 {
		result := s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(updates)
		if result.Error != nil {
			return nil, status.Error(codes.Internal, "Failed to update referral settings")
		}
		if result.RowsAffected == 0 {
			return nil, status.Error(codes.NotFound, "User not found")
		}
	}

	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}
	var subscription *model.PlanSubscription
	var subscriptionRecord model.PlanSubscription
	if err := s.db.WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").First(&subscriptionRecord).Error; err == nil {
		subscription = &subscriptionRecord
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}
	payload, err := s.buildAdminUserDetail(ctx, &user, subscription)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}
	return &appv1.UpdateAdminUserReferralSettingsResponse{User: payload}, nil
}
func (s *appServices) UpdateAdminUserRole(ctx context.Context, req *appv1.UpdateAdminUserRoleRequest) (*appv1.UpdateAdminUserRoleResponse, error) {
	adminResult, err := s.requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	if id == adminResult.UserID {
		return nil, status.Error(codes.InvalidArgument, "Cannot change your own role")
	}

	role := normalizeAdminRoleValue(req.GetRole())
	if !isValidAdminRoleValue(role) {
		return nil, status.Error(codes.InvalidArgument, "Invalid role. Must be USER, ADMIN, or BLOCK")
	}

	result := s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Update("role", role)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to update role")
	}
	if result.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	return &appv1.UpdateAdminUserRoleResponse{Message: "Role updated", Role: role}, nil
}
func (s *appServices) DeleteAdminUser(ctx context.Context, req *appv1.DeleteAdminUserRequest) (*appv1.MessageResponse, error) {
	adminResult, err := s.requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	if id == adminResult.UserID {
		return nil, status.Error(codes.InvalidArgument, "Cannot delete your own account")
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to find user")
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tables := []struct {
			model interface{}
			where string
		}{
			{&model.AdTemplate{}, "user_id = ?"},
			{&model.Notification{}, "user_id = ?"},
			{&model.Domain{}, "user_id = ?"},
			{&model.WalletTransaction{}, "user_id = ?"},
			{&model.PlanSubscription{}, "user_id = ?"},
			{&model.UserPreference{}, "user_id = ?"},
			{&model.Video{}, "user_id = ?"},
			{&model.Payment{}, "user_id = ?"},
		}
		for _, item := range tables {
			if err := tx.Where(item.where, id).Delete(item.model).Error; err != nil {
				return err
			}
		}
		return tx.Where("id = ?", id).Delete(&model.User{}).Error
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete user")
	}

	return messageResponse("User deleted"), nil
}
func (s *appServices) ListAdminVideos(ctx context.Context, req *appv1.ListAdminVideosRequest) (*appv1.ListAdminVideosResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	limitInt := int(limit)
	search := strings.TrimSpace(req.GetSearch())
	userID := strings.TrimSpace(req.GetUserId())
	statusFilter := strings.TrimSpace(req.GetStatus())

	db := s.db.WithContext(ctx).Model(&model.Video{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("title ILIKE ?", like)
	}
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if statusFilter != "" && !strings.EqualFold(statusFilter, "all") {
		db = db.Where("status = ?", normalizeVideoStatusValue(statusFilter))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list videos")
	}

	var videos []model.Video
	if err := db.Order("created_at DESC").Offset(offset).Limit(limitInt).Find(&videos).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to list videos")
	}

	items := make([]*appv1.AdminVideo, 0, len(videos))
	for _, video := range videos {
		payload, err := s.buildAdminVideo(ctx, &video)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to list videos")
		}
		items = append(items, payload)
	}

	return &appv1.ListAdminVideosResponse{Videos: items, Total: total, Page: page, Limit: limit}, nil
}
func (s *appServices) GetAdminVideo(ctx context.Context, req *appv1.GetAdminVideoRequest) (*appv1.GetAdminVideoResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get video")
	}

	payload, err := s.buildAdminVideo(ctx, &video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get video")
	}

	return &appv1.GetAdminVideoResponse{Video: payload}, nil
}
func (s *appServices) CreateAdminVideo(ctx context.Context, req *appv1.CreateAdminVideoRequest) (*appv1.CreateAdminVideoResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.videoService == nil {
		return nil, status.Error(codes.Unavailable, "Job service is unavailable")
	}

	userID := strings.TrimSpace(req.GetUserId())
	title := strings.TrimSpace(req.GetTitle())
	videoURL := strings.TrimSpace(req.GetUrl())
	if userID == "" || title == "" || videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID, title, and URL are required")
	}
	if req.GetSize() < 0 {
		return nil, status.Error(codes.InvalidArgument, "Size must be greater than or equal to 0")
	}

	created, err := s.videoService.CreateVideo(ctx, video.CreateVideoInput{
		UserID:       userID,
		Title:        title,
		Description:  req.Description,
		URL:          videoURL,
		Size:         req.GetSize(),
		Duration:     req.GetDuration(),
		Format:       strings.TrimSpace(req.GetFormat()),
		AdTemplateID: nullableTrimmedString(req.AdTemplateId),
	})
	if err != nil {
		switch {
		case errors.Is(err, video.ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "User not found")
		case errors.Is(err, video.ErrAdTemplateNotFound):
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		case errors.Is(err, video.ErrJobServiceUnavailable):
			return nil, status.Error(codes.Unavailable, "Job service is unavailable")
		default:
			return nil, status.Error(codes.Internal, "Failed to create video")
		}
	}

	payload, err := s.buildAdminVideo(ctx, created.Video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create video")
	}
	return &appv1.CreateAdminVideoResponse{Video: payload}, nil
}
func (s *appServices) UpdateAdminVideo(ctx context.Context, req *appv1.UpdateAdminVideoRequest) (*appv1.UpdateAdminVideoResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	userID := strings.TrimSpace(req.GetUserId())
	title := strings.TrimSpace(req.GetTitle())
	videoURL := strings.TrimSpace(req.GetUrl())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}
	if userID == "" || title == "" || videoURL == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID, title, and URL are required")
	}
	if req.GetSize() < 0 {
		return nil, status.Error(codes.InvalidArgument, "Size must be greater than or equal to 0")
	}

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	oldSize := video.Size
	oldUserID := video.UserID
	statusValue := normalizeVideoStatusValue(req.GetStatus())
	processingStatus := strings.ToUpper(statusValue)
	video.UserID = user.ID
	video.Name = title
	video.Title = title
	video.Description = nullableTrimmedString(req.Description)
	video.URL = videoURL
	video.Size = req.GetSize()
	video.Duration = req.GetDuration()
	video.Format = strings.TrimSpace(req.GetFormat())
	video.Status = model.StringPtr(statusValue)
	video.ProcessingStatus = model.StringPtr(processingStatus)
	video.StorageType = model.StringPtr(detectStorageType(videoURL))

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&video).Error; err != nil {
			return err
		}
		if oldUserID == user.ID {
			delta := video.Size - oldSize
			if delta != 0 {
				if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used + ?, 0)", delta)).Error; err != nil {
					return err
				}
			}
		} else {
			if err := tx.Model(&model.User{}).Where("id = ?", oldUserID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", oldSize)).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("storage_used", gorm.Expr("storage_used + ?", video.Size)).Error; err != nil {
				return err
			}
		}
		return s.saveAdminVideoAdConfig(ctx, tx, &video, user.ID, nullableTrimmedString(req.AdTemplateId))
	})
	if err != nil {
		if strings.Contains(err.Error(), "Ad template not found") {
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	payload, err := s.buildAdminVideo(ctx, &video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update video")
	}
	return &appv1.UpdateAdminVideoResponse{Video: payload}, nil
}
func (s *appServices) DeleteAdminVideo(ctx context.Context, req *appv1.DeleteAdminVideoRequest) (*appv1.MessageResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.NotFound, "Video not found")
	}

	var video model.Video
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&video).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to find video")
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", video.ID).Delete(&model.Video{}).Error; err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", video.UserID).UpdateColumn("storage_used", gorm.Expr("GREATEST(storage_used - ?, 0)", video.Size)).Error
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete video")
	}

	return messageResponse("Video deleted"), nil
}
