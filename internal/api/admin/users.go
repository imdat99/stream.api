//go:build ignore
// +build ignore

package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/pkg/response"
)

type AdminUserPayload struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Username      *string `json:"username"`
	Avatar        *string `json:"avatar"`
	Role          *string `json:"role"`
	PlanID        *string `json:"plan_id"`
	PlanName      string  `json:"plan_name,omitempty"`
	StorageUsed   int64   `json:"storage_used"`
	VideoCount    int64   `json:"video_count"`
	WalletBalance float64 `json:"wallet_balance"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type CreateAdminUserRequest struct {
	Email    string  `json:"email" binding:"required,email"`
	Username string  `json:"username"`
	Password string  `json:"password" binding:"required,min=6"`
	Role     string  `json:"role"`
	PlanID   *string `json:"plan_id"`
}

type UpdateAdminUserRequest struct {
	Email    *string `json:"email"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	Role     *string `json:"role"`
	PlanID   *string `json:"plan_id"`
}

type UpdateUserRoleRequest struct {
	Role string `json:"role" binding:"required"`
}

func normalizeAdminRole(value string) string {
	role := strings.ToUpper(strings.TrimSpace(value))
	if role == "" {
		return "USER"
	}
	return role
}

func isValidAdminRole(role string) bool {
	switch normalizeAdminRole(role) {
	case "USER", "ADMIN", "BLOCK":
		return true
	default:
		return false
	}
}

func (h *Handler) ensurePlanExists(ctx *gin.Context, planID *string) error {
	if planID == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*planID)
	if trimmed == "" {
		return nil
	}
	var count int64
	if err := h.db.WithContext(ctx.Request.Context()).Model(&model.Plan{}).Where("id = ?", trimmed).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// @Summary      List Users
// @Description  Get paginated list of all users (admin only)
// @Tags         admin
// @Produce      json
// @Param        page query int false "Page" default(1)
// @Param        limit query int false "Limit" default(20)
// @Param        search query string false "Search by email or username"
// @Param        role query string false "Filter by role"
// @Success      200  {object}  response.Response
// @Failure      401  {object}  response.Response
// @Failure      403  {object}  response.Response
// @Router       /admin/users [get]
// @Security     BearerAuth
func (h *Handler) ListUsers(c *gin.Context) {
	ctx := c.Request.Context()
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	search := strings.TrimSpace(c.Query("search"))
	role := strings.TrimSpace(c.Query("role"))

	db := h.db.WithContext(ctx).Model(&model.User{})
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("email ILIKE ? OR username ILIKE ?", like, like)
	}
	if role != "" {
		db = db.Where("UPPER(role) = ?", strings.ToUpper(role))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		h.logger.Error("Failed to count users", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list users")
		return
	}

	var users []model.User
	if err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		h.logger.Error("Failed to list users", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to list users")
		return
	}

	planIDs := map[string]bool{}
	for _, u := range users {
		if u.PlanID != nil && strings.TrimSpace(*u.PlanID) != "" {
			planIDs[*u.PlanID] = true
		}
	}
	planNames := map[string]string{}
	if len(planIDs) > 0 {
		ids := make([]string, 0, len(planIDs))
		for id := range planIDs {
			ids = append(ids, id)
		}
		var plans []model.Plan
		h.db.WithContext(ctx).Where("id IN ?", ids).Find(&plans)
		for _, p := range plans {
			planNames[p.ID] = p.Name
		}
	}

	result := make([]AdminUserPayload, 0, len(users))
	for _, u := range users {
		payload := AdminUserPayload{
			ID:          u.ID,
			Email:       u.Email,
			Username:    u.Username,
			Avatar:      u.Avatar,
			Role:        u.Role,
			PlanID:      u.PlanID,
			StorageUsed: u.StorageUsed,
			CreatedAt:   adminFormatTime(u.CreatedAt),
			UpdatedAt:   adminFormatTimeValue(u.UpdatedAt),
		}
		if u.PlanID != nil {
			payload.PlanName = planNames[*u.PlanID]
		}
		h.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", u.ID).Count(&payload.VideoCount)
		payload.WalletBalance, _ = model.GetWalletBalance(ctx, h.db, u.ID)
		result = append(result, payload)
	}

	response.Success(c, gin.H{
		"users": result,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// @Summary      Create User
// @Description  Create a user from admin panel (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request body CreateAdminUserRequest true "User payload"
// @Success      201  {object}  response.Response
// @Router       /admin/users [post]
// @Security     BearerAuth
func (h *Handler) CreateUser(c *gin.Context) {
	var req CreateAdminUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	role := normalizeAdminRole(req.Role)
	if !isValidAdminRole(role) {
		response.Error(c, http.StatusBadRequest, "Invalid role. Must be USER, ADMIN, or BLOCK")
		return
	}
	if err := h.ensurePlanExists(c, req.PlanID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Error(c, http.StatusBadRequest, "Plan not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to create user")
		return
	}

	email := strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to hash password")
		return
	}
	password := string(hashedPassword)

	user := &model.User{
		ID:       uuid.New().String(),
		Email:    email,
		Password: &password,
		Username: adminStringPtr(username),
		Role:     &role,
		PlanID:   nil,
	}
	if req.PlanID != nil && strings.TrimSpace(*req.PlanID) != "" {
		planID := strings.TrimSpace(*req.PlanID)
		user.PlanID = &planID
	}

	if err := h.db.WithContext(c.Request.Context()).Create(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			response.Error(c, http.StatusBadRequest, "Email already registered")
			return
		}
		h.logger.Error("Failed to create user", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to create user")
		return
	}

	response.Created(c, gin.H{"user": user})
}

// @Summary      Get User Detail
// @Description  Get detailed info about a single user (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Router       /admin/users/{id} [get]
// @Security     BearerAuth
func (h *Handler) GetUser(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")

	var user model.User
	if err := h.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to get user")
		return
	}

	var videoCount int64
	h.db.WithContext(ctx).Model(&model.Video{}).Where("user_id = ?", id).Count(&videoCount)
	balance, _ := model.GetWalletBalance(ctx, h.db, id)

	planName := ""
	if user.PlanID != nil {
		var plan model.Plan
		if err := h.db.WithContext(ctx).Where("id = ?", *user.PlanID).First(&plan).Error; err == nil {
			planName = plan.Name
		}
	}

	var subscription *model.PlanSubscription
	var sub model.PlanSubscription
	if err := h.db.WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").First(&sub).Error; err == nil {
		subscription = &sub
	}

	response.Success(c, gin.H{
		"user": gin.H{
			"id":           user.ID,
			"email":        user.Email,
			"username":     user.Username,
			"avatar":       user.Avatar,
			"role":         user.Role,
			"plan_id":      user.PlanID,
			"plan_name":    planName,
			"storage_used": user.StorageUsed,
			"created_at":   user.CreatedAt,
			"updated_at":   user.UpdatedAt,
		},
		"video_count":    videoCount,
		"wallet_balance": balance,
		"subscription":   subscription,
	})
}

// @Summary      Update User
// @Description  Update a user from admin panel (admin only)
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        request body UpdateAdminUserRequest true "User payload"
// @Success      200  {object}  response.Response
// @Router       /admin/users/{id} [put]
// @Security     BearerAuth
func (h *Handler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	currentUserID := c.GetString("userID")

	var req UpdateAdminUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	updates := map[string]interface{}{}
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			response.Error(c, http.StatusBadRequest, "Email is required")
			return
		}
		updates["email"] = email
	}
	if req.Username != nil {
		updates["username"] = strings.TrimSpace(*req.Username)
	}
	if req.Role != nil {
		role := normalizeAdminRole(*req.Role)
		if !isValidAdminRole(role) {
			response.Error(c, http.StatusBadRequest, "Invalid role. Must be USER, ADMIN, or BLOCK")
			return
		}
		if id == currentUserID && role != "ADMIN" {
			response.Error(c, http.StatusBadRequest, "Cannot change your own role")
			return
		}
		updates["role"] = role
	}
	if req.PlanID != nil {
		if err := h.ensurePlanExists(c, req.PlanID); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response.Error(c, http.StatusBadRequest, "Plan not found")
				return
			}
			response.Error(c, http.StatusInternalServerError, "Failed to update user")
			return
		}
		trimmed := strings.TrimSpace(*req.PlanID)
		if trimmed == "" {
			updates["plan_id"] = nil
		} else {
			updates["plan_id"] = trimmed
		}
	}
	if req.Password != nil {
		if strings.TrimSpace(*req.Password) == "" {
			response.Error(c, http.StatusBadRequest, "Password must not be empty")
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			response.Error(c, http.StatusInternalServerError, "Failed to hash password")
			return
		}
		updates["password"] = string(hashedPassword)
	}

	if len(updates) == 0 {
		response.Success(c, gin.H{"message": "No changes provided"})
		return
	}

	result := h.db.WithContext(c.Request.Context()).Model(&model.User{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			response.Error(c, http.StatusBadRequest, "Email already registered")
			return
		}
		h.logger.Error("Failed to update user", "error", result.Error)
		response.Error(c, http.StatusInternalServerError, "Failed to update user")
		return
	}
	if result.RowsAffected == 0 {
		response.Error(c, http.StatusNotFound, "User not found")
		return
	}

	var user model.User
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&user).Error; err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to reload user")
		return
	}

	response.Success(c, gin.H{"user": user})
}

// @Summary      Update User Role
// @Description  Change user role (admin only). Valid: USER, ADMIN, BLOCK
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        request body UpdateUserRoleRequest true "Role payload"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Router       /admin/users/{id}/role [put]
// @Security     BearerAuth
func (h *Handler) UpdateUserRole(c *gin.Context) {
	id := c.Param("id")
	currentUserID := c.GetString("userID")
	if id == currentUserID {
		response.Error(c, http.StatusBadRequest, "Cannot change your own role")
		return
	}

	var req UpdateUserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	role := normalizeAdminRole(req.Role)
	if !isValidAdminRole(role) {
		response.Error(c, http.StatusBadRequest, "Invalid role. Must be USER, ADMIN, or BLOCK")
		return
	}

	result := h.db.WithContext(c.Request.Context()).Model(&model.User{}).Where("id = ?", id).Update("role", role)
	if result.Error != nil {
		h.logger.Error("Failed to update user role", "error", result.Error)
		response.Error(c, http.StatusInternalServerError, "Failed to update role")
		return
	}
	if result.RowsAffected == 0 {
		response.Error(c, http.StatusNotFound, "User not found")
		return
	}

	response.Success(c, gin.H{"message": "Role updated", "role": role})
}

// @Summary      Delete User
// @Description  Delete a user and their data (admin only)
// @Tags         admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200  {object}  response.Response
// @Failure      400  {object}  response.Response
// @Failure      404  {object}  response.Response
// @Router       /admin/users/{id} [delete]
// @Security     BearerAuth
func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	currentUserID := c.GetString("userID")
	if id == currentUserID {
		response.Error(c, http.StatusBadRequest, "Cannot delete your own account")
		return
	}

	var user model.User
	if err := h.db.WithContext(c.Request.Context()).Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, http.StatusNotFound, "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "Failed to find user")
		return
	}

	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		tables := []struct {
			model interface{}
			where string
		}{
			{&model.VideoAdConfig{}, "user_id = ?"},
			{&model.AdTemplate{}, "user_id = ?"},
			{&model.Notification{}, "user_id = ?"},
			{&model.Domain{}, "user_id = ?"},
			{&model.WalletTransaction{}, "user_id = ?"},
			{&model.PlanSubscription{}, "user_id = ?"},
			{&model.UserPreference{}, "user_id = ?"},
			{&model.Video{}, "user_id = ?"},
			{&model.Payment{}, "user_id = ?"},
		}
		for _, t := range tables {
			if err := tx.Where(t.where, id).Delete(t.model).Error; err != nil {
				return err
			}
		}
		return tx.Where("id = ?", id).Delete(&model.User{}).Error
	})
	if err != nil {
		h.logger.Error("Failed to delete user", "error", err)
		response.Error(c, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	response.Success(c, gin.H{"message": "User deleted"})
}
