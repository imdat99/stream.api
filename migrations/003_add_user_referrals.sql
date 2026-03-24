-- Migration: Add user referral state
-- Created: 2026-03-23
-- Description: Adds minimal referral linkage and first-subscription reward tracking fields to user

BEGIN;

ALTER TABLE "user"
    ADD COLUMN IF NOT EXISTS referred_by_user_id UUID REFERENCES "user"(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS referral_eligible BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS referral_reward_bps INTEGER,
    ADD COLUMN IF NOT EXISTS referral_reward_granted_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS referral_reward_payment_id UUID,
    ADD COLUMN IF NOT EXISTS referral_reward_amount NUMERIC(65,30);

CREATE INDEX IF NOT EXISTS idx_user_referred_by_user_id ON "user"(referred_by_user_id);

COMMIT;
