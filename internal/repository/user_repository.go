package repository

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"stream.api/internal/database/model"
	"stream.api/internal/database/query"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *userRepository {
	return &userRepository{db: db}
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	u := query.User
	return u.WithContext(ctx).Where(u.Email.Eq(strings.TrimSpace(email))).First()
}

func (r *userRepository) CountByEmail(ctx context.Context, email string) (int64, error) {
	u := query.User
	return u.WithContext(ctx).Where(u.Email.Eq(strings.TrimSpace(email))).Count()
}

func (r *userRepository) GetByID(ctx context.Context, userID string) (*model.User, error) {
	u := query.User
	return u.WithContext(ctx).Where(u.ID.Eq(strings.TrimSpace(userID))).First()
}

func (r *userRepository) ListForAdmin(ctx context.Context, search string, role string, limit int32, offset int) ([]model.User, int64, error) {
	db := r.db.WithContext(ctx).Model(&model.User{})
	if trimmedSearch := strings.TrimSpace(search); trimmedSearch != "" {
		like := "%" + trimmedSearch + "%"
		db = db.Where("email ILIKE ? OR username ILIKE ?", like, like)
	}
	if trimmedRole := strings.TrimSpace(role); trimmedRole != "" {
		db = db.Where("UPPER(role) = ?", strings.ToUpper(trimmedRole))
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var users []model.User
	if err := db.Order("created_at DESC").Offset(offset).Limit(int(limit)).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (r *userRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *userRepository) CountCreatedSince(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Where("created_at >= ?", since).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *userRepository) SumStorageUsed(ctx context.Context) (int64, error) {
	var total int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Select("COALESCE(SUM(storage_used), 0)").Scan(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func (r *userRepository) GetEmailByID(ctx context.Context, userID string) (*string, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Select("id, email").Where("id = ?", strings.TrimSpace(userID)).First(&user).Error; err != nil {
		return nil, err
	}
	return &user.Email, nil
}

func (r *userRepository) GetReferralSummaryByID(ctx context.Context, userID string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Select("id, email, username").Where("id = ?", strings.TrimSpace(userID)).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) CountByPlanID(ctx context.Context, planID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Where("plan_id = ?", strings.TrimSpace(planID)).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *userRepository) LockByIDTx(tx *gorm.DB, ctx context.Context, userID string) (*model.User, error) {
	trimmedUserID := strings.TrimSpace(userID)
	if tx.Dialector.Name() == "sqlite" {
		res := tx.WithContext(ctx).Exec("UPDATE user SET id = id WHERE id = ?", trimmedUserID)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, gorm.ErrRecordNotFound
		}
	}

	var user model.User
	if err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", trimmedUserID).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	return query.User.WithContext(ctx).Create(user)
}

func (r *userRepository) UpdateFieldsByID(ctx context.Context, userID string, updates map[string]any) error {
	return r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", strings.TrimSpace(userID)).Updates(updates).Error
}

func (r *userRepository) UpdateFieldsByIDTx(tx *gorm.DB, ctx context.Context, userID string, updates map[string]any) error {
	return tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", strings.TrimSpace(userID)).Updates(updates).Error
}

func (r *userRepository) UpdatePassword(ctx context.Context, userID string, passwordHash string) error {
	_, err := query.User.WithContext(ctx).
		Where(query.User.ID.Eq(strings.TrimSpace(userID))).
		Update(query.User.Password, passwordHash)
	return err
}

func (r *userRepository) FindByReferralUsername(ctx context.Context, username string, limit int) ([]model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil, nil
	}
	var users []model.User
	if err := r.db.WithContext(ctx).
		Where("LOWER(username) = LOWER(?)", trimmed).
		Order("created_at ASC, id ASC").
		Limit(limit).
		Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (r *userRepository) CountSubscriptionsByUser(ctx context.Context, userID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.PlanSubscription{}).
		Where("user_id = ?", strings.TrimSpace(userID)).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}
