package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"stream.api/internal/database/model"
)

func referralUserEligible(user *model.User) bool {
	if user == nil || user.ReferralEligible == nil {
		return true
	}
	return *user.ReferralEligible
}

func effectiveReferralRewardBps(value *int32) int32 {
	if value == nil {
		return defaultReferralRewardBps
	}
	if *value < 0 {
		return 0
	}
	if *value > 10000 {
		return 10000
	}
	return *value
}

func referralRewardBpsToPercent(value int32) float64 {
	return float64(value) / 100
}

func referralRewardProcessed(user *model.User) bool {
	if user == nil {
		return false
	}
	if user.ReferralRewardGrantedAt != nil {
		return true
	}
	if user.ReferralRewardPaymentID != nil && strings.TrimSpace(*user.ReferralRewardPaymentID) != "" {
		return true
	}
	return false
}

func sameTrimmedStringFold(left *string, right string) bool {
	if left == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(*left), strings.TrimSpace(right))
}

func (s *appServices) buildReferralShareLink(username *string) *string {
	trimmed := strings.TrimSpace(stringValue(username))
	if trimmed == "" {
		return nil
	}
	path := "/ref/" + url.PathEscape(trimmed)
	base := strings.TrimRight(strings.TrimSpace(s.frontendBaseURL), "/")
	if base == "" {
		return &path
	}
	link := base + path
	return &link
}

func (s *appServices) loadReferralUsersByUsername(ctx context.Context, username string) ([]model.User, error) {
	return s.userRepository.FindByReferralUsername(ctx, username, 2)
}

func (s *appServices) resolveReferralUserByUsername(ctx context.Context, username string) (*model.User, error) {
	users, err := s.loadReferralUsersByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, nil
	}
	return &users[0], nil
}

func (s *appServices) loadReferralUserByUsernameStrict(ctx context.Context, username string) (*model.User, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil, status.Error(codes.InvalidArgument, "Referral username is required")
	}
	users, err := s.loadReferralUsersByUsername(ctx, trimmed)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to resolve referral user")
	}
	if len(users) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Referral user not found")
	}
	if len(users) > 1 {
		return nil, status.Error(codes.InvalidArgument, "Referral username is ambiguous")
	}
	return &users[0], nil
}

func (s *appServices) resolveSignupReferrerID(ctx context.Context, refUsername string, newUsername string) (*string, error) {
	trimmedRefUsername := strings.TrimSpace(refUsername)
	if trimmedRefUsername == "" || strings.EqualFold(trimmedRefUsername, strings.TrimSpace(newUsername)) {
		return nil, nil
	}
	referrer, err := s.resolveReferralUserByUsername(ctx, trimmedRefUsername)
	if err != nil {
		return nil, err
	}
	if referrer == nil {
		return nil, nil
	}
	return &referrer.ID, nil
}

func buildReferralRewardNotification(userID string, rewardAmount float64, referee *model.User, paymentRecord *model.Payment) *model.Notification {
	refereeLabel := strings.TrimSpace(referee.Email)
	if username := strings.TrimSpace(stringValue(referee.Username)); username != "" {
		refereeLabel = "@" + username
	}
	return &model.Notification{
		ID:      uuid.New().String(),
		UserID:  userID,
		Type:    "billing.referral_reward",
		Title:   "Referral reward granted",
		Message: fmt.Sprintf("You received %.2f USD from %s's first subscription.", rewardAmount, refereeLabel),
		Metadata: model.StringPtr(mustMarshalJSON(map[string]any{
			"payment_id": paymentRecord.ID,
			"referee_id": referee.ID,
			"amount":     rewardAmount,
		})),
	}
}

func (s *appServices) maybeGrantReferralReward(ctx context.Context, tx *gorm.DB, input paymentExecutionInput, paymentRecord *model.Payment, subscription *model.PlanSubscription) (*referralRewardResult, error) {
	if paymentRecord == nil || subscription == nil || input.Plan == nil {
		return &referralRewardResult{}, nil
	}
	if subscription.PaymentMethod != paymentMethodWallet && subscription.PaymentMethod != paymentMethodTopup {
		return &referralRewardResult{}, nil
	}

	referee, err := s.userRepository.LockByIDTx(tx, ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if referee.ReferredByUserID == nil || strings.TrimSpace(*referee.ReferredByUserID) == "" {
		return &referralRewardResult{}, nil
	}
	if referralRewardProcessed(referee) {
		return &referralRewardResult{}, nil
	}

	subscriptionCount, err := s.userRepository.CountSubscriptionsByUser(ctx, referee.ID)
	if err != nil {
		return nil, err
	}
	if subscriptionCount != 1 {
		return &referralRewardResult{}, nil
	}

	referrer, err := s.userRepository.LockByIDTx(tx, ctx, strings.TrimSpace(*referee.ReferredByUserID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &referralRewardResult{}, nil
		}
		return nil, err
	}
	if referrer.ID == referee.ID || !referralUserEligible(referrer) {
		return &referralRewardResult{}, nil
	}

	bps := effectiveReferralRewardBps(referrer.ReferralRewardBps)
	if bps <= 0 {
		return &referralRewardResult{}, nil
	}
	baseAmount := input.Plan.Price * float64(input.TermMonths)
	if baseAmount <= 0 {
		return &referralRewardResult{}, nil
	}
	rewardAmount := baseAmount * float64(bps) / 10000
	if rewardAmount <= 0 {
		return &referralRewardResult{}, nil
	}

	currency := normalizeCurrency(paymentRecord.Currency)
	rewardTransaction := &model.WalletTransaction{
		ID:        uuid.New().String(),
		UserID:    referrer.ID,
		Type:      walletTransactionTypeReferralReward,
		Amount:    rewardAmount,
		Currency:  model.StringPtr(currency),
		Note:      model.StringPtr(fmt.Sprintf("Referral reward for %s first subscription", referee.Email)),
		PaymentID: &paymentRecord.ID,
		PlanID:    &input.Plan.ID,
	}
	if err := s.paymentRepository.CreateWalletTransactionTx(tx, ctx, rewardTransaction); err != nil {
		return nil, err
	}
	rewardNotification := buildReferralRewardNotification(referrer.ID, rewardAmount, referee, paymentRecord)
	if err := s.paymentRepository.CreateNotificationTx(tx, ctx, rewardNotification); err != nil {
		return nil, err
	}
	s.publishNotificationCreated(ctx, rewardNotification)

	now := time.Now().UTC()
	updates := map[string]any{
		"referral_reward_granted_at": now,
		"referral_reward_payment_id": paymentRecord.ID,
		"referral_reward_amount":     rewardAmount,
	}
	if err := s.userRepository.UpdateFieldsByIDTx(tx, ctx, referee.ID, updates); err != nil {
		return nil, err
	}
	referee.ReferralRewardGrantedAt = &now
	referee.ReferralRewardPaymentID = &paymentRecord.ID
	referee.ReferralRewardAmount = &rewardAmount
	return &referralRewardResult{Granted: true, Amount: rewardAmount}, nil
}
