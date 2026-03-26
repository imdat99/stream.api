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
)

func (s *appServices) GetAdminDashboard(ctx context.Context, _ *appv1.GetAdminDashboardRequest) (*appv1.GetAdminDashboardResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	today := time.Now().Truncate(24 * time.Hour)
	totalUsers, err := s.userRepository.CountAll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	totalVideos, err := s.videoRepository.CountAll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	totalStorageUsed, err := s.userRepository.SumStorageUsed(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	totalPayments, err := s.paymentRepository.CountAll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	totalRevenue, err := s.paymentRepository.SumSuccessfulAmount(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	activeSubscriptions, err := s.billingRepository.CountActiveSubscriptions(ctx, time.Now())
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	totalAdTemplates, err := s.adTemplateRepository.CountAll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	newUsersToday, err := s.userRepository.CountCreatedSince(ctx, today)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}
	newVideosToday, err := s.videoRepository.CountCreatedSince(ctx, today)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load dashboard")
	}

	dashboard := &appv1.AdminDashboard{
		TotalUsers:          totalUsers,
		TotalVideos:         totalVideos,
		TotalStorageUsed:    totalStorageUsed,
		TotalPayments:       totalPayments,
		TotalRevenue:        totalRevenue,
		ActiveSubscriptions: activeSubscriptions,
		TotalAdTemplates:    totalAdTemplates,
		NewUsersToday:       newUsersToday,
		NewVideosToday:      newVideosToday,
	}

	return &appv1.GetAdminDashboardResponse{Dashboard: dashboard}, nil
}
func (s *appServices) ListAdminUsers(ctx context.Context, req *appv1.ListAdminUsersRequest) (*appv1.ListAdminUsersResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}

	page, limit, offset := adminPageLimitOffset(req.GetPage(), req.GetLimit())
	search := strings.TrimSpace(req.GetSearch())
	role := strings.TrimSpace(req.GetRole())

	users, total, err := s.userRepository.ListForAdmin(ctx, search, role, limit, offset)
	if err != nil {
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

	user, err := s.userRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get user")
	}

	var subscription *model.PlanSubscription
	if subscriptionRecord, err := s.billingRepository.GetLatestPlanSubscription(ctx, id); err == nil {
		subscription = subscriptionRecord
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.Internal, "Failed to get user")
	}

	detail, err := s.buildAdminUserDetail(ctx, user, subscription)
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

	if err := s.userRepository.Create(ctx, user); err != nil {
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
		user, err := s.userRepository.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, status.Error(codes.NotFound, "User not found")
			}
			return nil, status.Error(codes.Internal, "Failed to update user")
		}
		payload, err := s.buildAdminUser(ctx, user)
		if err != nil {
			return nil, status.Error(codes.Internal, "Failed to update user")
		}
		return &appv1.UpdateAdminUserResponse{User: payload}, nil
	}

	if _, err := s.userRepository.GetByID(ctx, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update user")
	}
	if err := s.userRepository.UpdateFieldsByID(ctx, id, updates); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, "Email already registered")
		}
		return nil, status.Error(codes.Internal, "Failed to update user")
	}

	user, err := s.userRepository.GetByID(ctx, id)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update user")
	}
	payload, err := s.buildAdminUser(ctx, user)
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

	user, err := s.userRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}

	updates := map[string]any{}
	if req.RefUsername != nil || (req.ClearReferrer != nil && req.GetClearReferrer()) {
		if referralRewardProcessed(user) {
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
		if err := s.userRepository.UpdateFieldsByID(ctx, id, updates); err != nil {
			return nil, status.Error(codes.Internal, "Failed to update referral settings")
		}
	}

	user, err = s.userRepository.GetByID(ctx, id)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}
	var subscription *model.PlanSubscription
	if subscriptionRecord, err := s.billingRepository.GetLatestPlanSubscription(ctx, id); err == nil {
		subscription = subscriptionRecord
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.Internal, "Failed to update referral settings")
	}
	payload, err := s.buildAdminUserDetail(ctx, user, subscription)
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

	if _, err := s.userRepository.GetByID(ctx, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update role")
	}
	if err := s.userRepository.UpdateFieldsByID(ctx, id, map[string]any{"role": role}); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update role")
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

	if _, err := s.userRepository.GetByID(ctx, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		return nil, status.Error(codes.Internal, "Failed to find user")
	}

	err = s.accountRepository.DeleteUserAccount(ctx, id)
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
	search := strings.TrimSpace(req.GetSearch())
	userID := strings.TrimSpace(req.GetUserId())
	statusFilter := strings.TrimSpace(req.GetStatus())

	videos, total, err := s.videoRepository.ListForAdmin(ctx, search, userID, normalizeVideoStatusValue(statusFilter), offset, int(limit))
	if err != nil {
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

	video, err := s.videoRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get video")
	}

	payload, err := s.buildAdminVideo(ctx, video)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get video")
	}

	return &appv1.GetAdminVideoResponse{Video: payload}, nil
}
func (s *appServices) CreateAdminVideo(ctx context.Context, req *appv1.CreateAdminVideoRequest) (*appv1.CreateAdminVideoResponse, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.videoWorkflowService == nil {
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

	created, err := s.videoWorkflowService.CreateVideo(ctx, CreateVideoInput{
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
		case errors.Is(err, ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "User not found")
		case errors.Is(err, ErrAdTemplateNotFound):
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		case errors.Is(err, ErrJobServiceUnavailable):
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

	video, err := s.videoRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	user, err := s.userRepository.GetByID(ctx, userID)
	if err != nil {
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

	err = s.videoRepository.UpdateAdminVideo(ctx, video, oldUserID, oldSize, nullableTrimmedString(req.AdTemplateId))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.InvalidArgument, "Ad template not found")
		}
		return nil, status.Error(codes.Internal, "Failed to update video")
	}

	payload, err := s.buildAdminVideo(ctx, video)
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

	video, err := s.videoRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "Video not found")
		}
		return nil, status.Error(codes.Internal, "Failed to find video")
	}

	if err := s.videoRepository.DeleteByIDWithStorageUpdate(ctx, video.ID, video.UserID, video.Size); err != nil {
		return nil, status.Error(codes.Internal, "Failed to delete video")
	}

	return messageResponse("Video deleted"), nil
}
