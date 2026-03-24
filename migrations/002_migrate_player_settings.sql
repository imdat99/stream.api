-- Migration: Migrate player settings from user_preferences to player_configs
-- Created: 2026-03-19
-- Description:
--   1. Creates player_configs records from existing user_preferences player settings
--   2. Removes player-related columns from user_preferences table
--   3. Removes encrytion_m3u8 column (VIP feature not in use)
--
-- IMPORTANT: Run this AFTER 001_create_player_configs_table.sql
-- Usage: psql -h <host> -U postgres -d video_db -f 002_migrate_player_settings.sql

BEGIN;

-- ============================================================
-- STEP 1: Migrate existing player settings to player_configs
-- ============================================================

-- Insert player configs for all users that have user_preferences
-- Each user gets one default config with their existing settings
INSERT INTO player_configs (
    id,
    user_id,
    name,
    description,
    autoplay,
    loop,
    muted,
    show_controls,
    pip,
    airplay,
    chromecast,
    is_active,
    is_default,
    created_at,
    updated_at,
    version
)
SELECT
    gen_random_uuid() AS id,
    up.user_id,
    'Default Config' AS name,
    'Migrated from user_preferences' AS description,
    COALESCE(up.autoplay, FALSE) AS autoplay,
    COALESCE(up.loop, FALSE) AS loop,
    COALESCE(up.muted, FALSE) AS muted,
    COALESCE(up.show_controls, TRUE) AS show_controls,
    COALESCE(up.pip, TRUE) AS pip,
    COALESCE(up.airplay, TRUE) AS airplay,
    COALESCE(up.chromecast, TRUE) AS chromecast,
    TRUE AS is_active,
    TRUE AS is_default,
    COALESCE(up.created_at, CURRENT_TIMESTAMP) AS created_at,
    CURRENT_TIMESTAMP AS updated_at,
    COALESCE(up.version, 1) AS version
FROM user_preferences up
WHERE NOT EXISTS (
    -- Skip if user already has a player config (from previous migration)
    SELECT 1 FROM player_configs pc WHERE pc.user_id = up.user_id AND pc.is_default = TRUE
);

-- Also handle users that exist in "user" table but don't have user_preferences yet
-- They won't get a config now, but will get default values when they first access settings

-- ============================================================
-- STEP 2: Remove player-related columns from user_preferences
-- ============================================================

-- Drop player settings columns
ALTER TABLE user_preferences
    DROP COLUMN IF EXISTS autoplay,
    DROP COLUMN IF EXISTS loop,
    DROP COLUMN IF EXISTS muted,
    DROP COLUMN IF EXISTS show_controls,
    DROP COLUMN IF EXISTS pip,
    DROP COLUMN IF EXISTS airplay,
    DROP COLUMN IF EXISTS chromecast;

-- Drop encrytion_m3u8 column (VIP feature not in use)
ALTER TABLE user_preferences
    DROP COLUMN IF EXISTS encrytion_m3u8;

-- ============================================================
-- STEP 3: Add constraint to ensure one default config per user
-- ============================================================

-- Create a partial unique index to ensure only one is_default = TRUE per user
-- This prevents multiple default configs per user
CREATE UNIQUE INDEX IF NOT EXISTS idx_player_configs_one_default_per_user
ON player_configs(user_id)
WHERE is_default = TRUE;

-- ============================================================
-- STEP 4: Verify migration
-- ============================================================

-- Count migrated configs
DO $$
DECLARE
    migrated_count INTEGER;
    user_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO migrated_count FROM player_configs WHERE description = 'Migrated from user_preferences';
    SELECT COUNT(*) INTO user_count FROM "user";

    RAISE NOTICE '============================================';
    RAISE NOTICE 'Migration completed successfully!';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Users in system: %', user_count;
    RAISE NOTICE 'Player configs created: %', migrated_count;
    RAISE NOTICE '============================================';
END $$;

COMMIT;

-- ============================================================
-- Verification queries (run after migration)
-- ============================================================

-- Verify player_configs structure
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'player_configs'
ORDER BY ordinal_position;

-- Verify user_preferences structure (should not have player columns anymore)
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'user_preferences'
ORDER BY ordinal_position;

-- Sample migrated data
SELECT pc.user_id, pc.name, pc.autoplay, pc.loop, pc.muted, pc.is_default
FROM player_configs pc
WHERE pc.description = 'Migrated from user_preferences'
LIMIT 5;
