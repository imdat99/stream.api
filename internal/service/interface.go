package service

import (
	"context"
	"time"

	"gorm.io/gorm"
	"stream.api/internal/database/model"
	"stream.api/internal/dto"
	"stream.api/internal/repository"
	renderworkflow "stream.api/internal/workflow/render"
)

type PaymentHistoryRow = repository.PaymentHistoryRow
type CreateVideoInput = renderworkflow.CreateVideoInput
type CreateVideoResult = renderworkflow.CreateVideoResult

var (
	ErrUserNotFound          = renderworkflow.ErrUserNotFound
	ErrAdTemplateNotFound    = renderworkflow.ErrAdTemplateNotFound
	ErrJobServiceUnavailable = renderworkflow.ErrJobServiceUnavailable
)

type PaymentRepository interface {
	ListHistoryByUser(ctx context.Context, userID string, subscriptionKind string, walletTopupKind string, topupType string, limit int32, offset int) ([]PaymentHistoryRow, int64, error)
	ListForAdmin(ctx context.Context, userID string, status string, limit int32, offset int) ([]model.Payment, int64, error)
	CountAll(ctx context.Context) (int64, error)
	SumSuccessfulAmount(ctx context.Context) (float64, error)
	GetByIDAndUser(ctx context.Context, paymentID string, userID string) (*model.Payment, error)
	GetByID(ctx context.Context, paymentID string) (*model.Payment, error)
	GetStandaloneTopupByIDAndUser(ctx context.Context, id string, userID string, topupType string) (*model.WalletTransaction, error)
	GetSubscriptionByPaymentID(ctx context.Context, paymentID string) (*model.PlanSubscription, error)
	CountByPlanID(ctx context.Context, planID string) (int64, error)
	CreatePayment(ctx context.Context, payment *model.Payment) error
	Save(ctx context.Context, payment *model.Payment) error
	CreatePaymentTx(tx *gorm.DB, ctx context.Context, payment *model.Payment) error
	CreateWalletTransactionTx(tx *gorm.DB, ctx context.Context, txRecord *model.WalletTransaction) error
	CreatePlanSubscriptionTx(tx *gorm.DB, ctx context.Context, subscription *model.PlanSubscription) error
	UpdateUserPlanID(ctx context.Context, userID string, planID string) error
	UpdateUserPlanIDTx(tx *gorm.DB, ctx context.Context, userID string, planID string) error
	CreateNotificationTx(tx *gorm.DB, ctx context.Context, notification *model.Notification) error
	CreateWalletTopupAndNotification(ctx context.Context, userID string, transaction *model.WalletTransaction, notification *model.Notification) error
	ExecuteSubscriptionPayment(ctx context.Context, userID string, plan *model.Plan, termMonths int32, paymentMethod string, paymentRecord *model.Payment, invoiceID string, now time.Time, validateFunding func(currentWalletBalance float64) (float64, error)) (*model.PlanSubscription, float64, error)
}

type NotificationEventPublisher interface {
	PublishNotificationCreated(ctx context.Context, notification *model.Notification) error
}

type AccountRepository interface {
	DeleteUserAccount(ctx context.Context, userID string) error
	ClearUserData(ctx context.Context, userID string) error
}

type NotificationRepository interface {
	ListByUser(ctx context.Context, userID string) ([]model.Notification, error)
	MarkReadByIDAndUser(ctx context.Context, id string, userID string) (int64, error)
	MarkAllReadByUser(ctx context.Context, userID string) error
	DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error)
	DeleteAllByUser(ctx context.Context, userID string) error
}

type DomainRepository interface {
	ListByUser(ctx context.Context, userID string) ([]model.Domain, error)
	CountByUserAndName(ctx context.Context, userID string, name string) (int64, error)
	Create(ctx context.Context, item *model.Domain) error
	DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error)
}

type AdTemplateRepository interface {
	ListByUser(ctx context.Context, userID string) ([]model.AdTemplate, error)
	ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.AdTemplate, int64, error)
	CountAll(ctx context.Context) (int64, error)
	GetByID(ctx context.Context, id string) (*model.AdTemplate, error)
	GetByIDAndUser(ctx context.Context, id string, userID string) (*model.AdTemplate, error)
	ExistsByIDAndUser(ctx context.Context, id string, userID string) (bool, error)
	CreateWithDefault(ctx context.Context, userID string, item *model.AdTemplate) error
	SaveWithDefault(ctx context.Context, userID string, item *model.AdTemplate) error
	DeleteByIDAndUserAndClearVideos(ctx context.Context, id string, userID string) error
	DeleteByIDAndClearVideos(ctx context.Context, id string) error
}

type PopupAdRepository interface {
	ListByUser(ctx context.Context, userID string, limit int32, offset int) ([]model.PopupAd, int64, error)
	ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.PopupAd, int64, error)
	GetByID(ctx context.Context, id string) (*model.PopupAd, error)
	GetByIDAndUser(ctx context.Context, id string, userID string) (*model.PopupAd, error)
	GetActiveByUser(ctx context.Context, userID string) (*model.PopupAd, error)
	Create(ctx context.Context, item *model.PopupAd) error
	Save(ctx context.Context, item *model.PopupAd) error
	DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error)
	DeleteByID(ctx context.Context, id string) (int64, error)
}

type PlayerConfigRepository interface {
	ListByUser(ctx context.Context, userID string) ([]model.PlayerConfig, error)
	ListForAdmin(ctx context.Context, search string, userID string, limit int32, offset int) ([]model.PlayerConfig, int64, error)
	CountByUser(ctx context.Context, userID string) (int64, error)
	CountByUserTx(tx *gorm.DB, ctx context.Context, userID string) (int64, error)
	Create(ctx context.Context, item *model.PlayerConfig) error
	CreateWithDefault(ctx context.Context, userID string, item *model.PlayerConfig) error
	CreateTx(tx *gorm.DB, ctx context.Context, item *model.PlayerConfig) error
	GetByID(ctx context.Context, id string) (*model.PlayerConfig, error)
	GetByIDAndUser(ctx context.Context, id string, userID string) (*model.PlayerConfig, error)
	GetByIDAndUserTx(tx *gorm.DB, ctx context.Context, id string, userID string) (*model.PlayerConfig, error)
	Save(ctx context.Context, item *model.PlayerConfig) error
	SaveWithDefault(ctx context.Context, userID string, item *model.PlayerConfig) error
	SaveTx(tx *gorm.DB, ctx context.Context, item *model.PlayerConfig) error
	DeleteByID(ctx context.Context, id string) (int64, error)
	DeleteByIDAndUser(ctx context.Context, id string, userID string) (int64, error)
	DeleteByIDAndUserTx(tx *gorm.DB, ctx context.Context, id string, userID string) (int64, error)
	UnsetDefaultForUser(ctx context.Context, userID string, excludeID string) error
	UnsetDefaultForUserTx(tx *gorm.DB, userID string, excludeID string) error
	CreateManaged(ctx context.Context, userID string, item *model.PlayerConfig, validate func(*model.User, int64) error) error
	DeleteManaged(ctx context.Context, userID string, id string, validate func(*model.User, int64) error) error
	UpdateManaged(ctx context.Context, userID string, id string, mutateAndValidate func(*model.PlayerConfig, *model.User, int64) error) (*model.PlayerConfig, error)
}

type VideoWorkflow interface {
	CreateVideo(ctx context.Context, input CreateVideoInput) (*CreateVideoResult, error)
	ListJobs(ctx context.Context, offset, limit int) (*dto.PaginatedJobs, error)
	ListJobsByAgent(ctx context.Context, agentID string, offset, limit int) (*dto.PaginatedJobs, error)
	ListJobsByCursor(ctx context.Context, agentID string, cursor string, pageSize int) (*dto.PaginatedJobs, error)
	GetJob(ctx context.Context, id string) (*model.Job, error)
	CreateJob(ctx context.Context, userID string, videoID string, name string, config []byte, priority int, timeLimit int64) (*model.Job, error)
	CancelJob(ctx context.Context, id string) error
	RetryJob(ctx context.Context, id string) (*model.Job, error)
}

type VideoRepository interface {
	ListByUser(ctx context.Context, userID string, search string, status string, offset int, limit int) ([]model.Video, int64, error)
	ListForAdmin(ctx context.Context, search string, userID string, status string, offset int, limit int) ([]model.Video, int64, error)
	CountAll(ctx context.Context) (int64, error)
	CountCreatedSince(ctx context.Context, since time.Time) (int64, error)
	IncrementViews(ctx context.Context, videoID string, userID string) error
	GetByID(ctx context.Context, videoID string) (*model.Video, error)
	GetByIDAndUser(ctx context.Context, videoID string, userID string) (*model.Video, error)
	UpdateByIDAndUser(ctx context.Context, videoID string, userID string, updates map[string]any) (int64, error)
	CountByUser(ctx context.Context, userID string) (int64, error)
	DeleteByIDAndUserWithStorageUpdate(ctx context.Context, videoID string, userID string, videoSize int64) error
	DeleteByIDWithStorageUpdate(ctx context.Context, videoID string, userID string, videoSize int64) error
	UpdateAdminVideo(ctx context.Context, video *model.Video, oldUserID string, oldSize int64, adTemplateID *string) error
}
type VideoWorkflowRepository interface {
	CreateVideoWithStorageAndAd(ctx context.Context, video *model.Video, userID string, adTemplateID *string) error
	GetUserByID(ctx context.Context, userID string) (*model.User, error)
	MarkVideoJobFailed(ctx context.Context, videoID string) error
}
type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	CountByEmail(ctx context.Context, email string) (int64, error)
	GetByID(ctx context.Context, userID string) (*model.User, error)
	LockByIDTx(tx *gorm.DB, ctx context.Context, userID string) (*model.User, error)
	ListForAdmin(ctx context.Context, search string, role string, limit int32, offset int) ([]model.User, int64, error)
	CountAll(ctx context.Context) (int64, error)
	CountCreatedSince(ctx context.Context, since time.Time) (int64, error)
	SumStorageUsed(ctx context.Context) (int64, error)
	GetEmailByID(ctx context.Context, userID string) (*string, error)
	GetReferralSummaryByID(ctx context.Context, userID string) (*model.User, error)
	CountByPlanID(ctx context.Context, planID string) (int64, error)
	Create(ctx context.Context, user *model.User) error
	UpdateFieldsByID(ctx context.Context, userID string, updates map[string]any) error
	UpdateFieldsByIDTx(tx *gorm.DB, ctx context.Context, userID string, updates map[string]any) error
	UpdatePassword(ctx context.Context, userID string, passwordHash string) error
	FindByReferralUsername(ctx context.Context, username string, limit int) ([]model.User, error)
	CountSubscriptionsByUser(ctx context.Context, userID string) (int64, error)
}

type UserPreferenceRepository interface {
	FindOrCreateByUserID(ctx context.Context, userID string) (*model.UserPreference, error)
	Save(ctx context.Context, pref *model.UserPreference) error
}

type BillingRepository interface {
	GetWalletBalance(ctx context.Context, userID string) (float64, error)
	GetWalletBalanceTx(tx *gorm.DB, ctx context.Context, userID string) (float64, error)
	GetLatestPlanSubscription(ctx context.Context, userID string) (*model.PlanSubscription, error)
	GetLatestPlanSubscriptionTx(tx *gorm.DB, ctx context.Context, userID string) (*model.PlanSubscription, error)
	CountActiveSubscriptions(ctx context.Context, now time.Time) (int64, error)
}

type PlanRepository interface {
	GetByID(ctx context.Context, planID string) (*model.Plan, error)
	ListActive(ctx context.Context) ([]model.Plan, error)
	ListAll(ctx context.Context) ([]model.Plan, error)
	Create(ctx context.Context, plan *model.Plan) error
	Save(ctx context.Context, plan *model.Plan) error
	CountPaymentsByPlan(ctx context.Context, planID string) (int64, error)
	CountSubscriptionsByPlan(ctx context.Context, planID string) (int64, error)
	SetActive(ctx context.Context, planID string, isActive bool) error
	DeleteByID(ctx context.Context, planID string) error
}

type JobRepository interface {
	Create(ctx context.Context, job *model.Job) error
	GetByID(ctx context.Context, id string) (*model.Job, error)
	GetLatestByVideoID(ctx context.Context, videoID string) (*model.Job, error)
	ListByCursor(ctx context.Context, agentID string, cursorTime time.Time, cursorID string, limit int) ([]*model.Job, bool, error)
	ListByOffset(ctx context.Context, agentID string, offset int, limit int) ([]*model.Job, int64, error)
	Save(ctx context.Context, job *model.Job) error
	UpdateVideoStatus(ctx context.Context, videoID string, statusValue string, processingStatus string) error
}

type AgentRuntime interface {
	ListAgentsWithStats() []*dto.AgentWithStats
	SendCommand(agentID string, cmd string) bool
}
