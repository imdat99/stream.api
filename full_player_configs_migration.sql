-- Full migration script for player_configs
-- This combines all migrations into one file for easy execution
-- Run: psql -h 47.84.63.130 -U postgres -d video_db -f full_player_configs_migration.sql

\echo '=============================================='
\echo 'Starting full player_configs migration...'
\echo '=============================================='

BEGIN;

-- ============================================================
-- PART 1: Create player_configs table
-- ============================================================

CREATE TABLE IF NOT EXISTS player_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    autoplay BOOLEAN NOT NULL DEFAULT FALSE,
    loop BOOLEAN NOT NULL DEFAULT FALSE,
    muted BOOLEAN NOT NULL DEFAULT FALSE,
    show_controls BOOLEAN NOT NULL DEFAULT TRUE,
    pip BOOLEAN NOT NULL DEFAULT TRUE,
    airplay BOOLEAN NOT NULL DEFAULT TRUE,
    chromecast BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(3) WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) WITHOUT TIME ZONE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_player_configs_user_id ON player_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_player_configs_is_default ON player_configs(is_default);
CREATE INDEX IF NOT EXISTS idx_player_configs_user_default ON player_configs(user_id, is_default);

CREATE OR REPLACE FUNCTION update_player_configs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_player_configs ON player_configs;

CREATE TRIGGER trg_update_player_configs
BEFORE UPDATE ON player_configs
FOR EACH ROW
EXECUTE FUNCTION update_player_configs_updated_at();

-- ============================================================
-- PART 2: Migrate data from user_preferences
-- ============================================================

INSERT INTO player_configs (
    id, user_id, name, description,
    autoplay, loop, muted,
    show_controls, pip, airplay, chromecast,
    is_active, is_default,
    created_at, updated_at, version
)
SELECT
    gen_random_uuid(),
    up.user_id,
    'Default Config',
    'Migrated from user_preferences',
    COALESCE(up.autoplay, FALSE),
    COALESCE(up.loop, FALSE),
    COALESCE(up.muted, FALSE),
    COALESCE(up.show_controls, TRUE),
    COALESCE(up.pip, TRUE),
    COALESCE(up.airplay, TRUE),
    COALESCE(up.chromecast, TRUE),
    TRUE,
    TRUE,
    COALESCE(up.created_at, CURRENT_TIMESTAMP),
    CURRENT_TIMESTAMP,
    COALESCE(up.version, 1)
FROM user_preferences up
WHERE NOT EXISTS (
    SELECT 1 FROM player_configs pc WHERE pc.user_id = up.user_id AND pc.is_default = TRUE
);

-- ============================================================
-- PART 3: Remove old columns from user_preferences
-- ============================================================

ALTER TABLE user_preferences
    DROP COLUMN IF EXISTS autoplay,
    DROP COLUMN IF EXISTS loop,
    DROP COLUMN IF EXISTS muted,
    DROP COLUMN IF EXISTS show_controls,
    DROP COLUMN IF EXISTS pip,
    DROP COLUMN IF EXISTS airplay,
    DROP COLUMN IF EXISTS chromecast,
    DROP COLUMN IF EXISTS encrytion_m3u8;

-- ============================================================
-- PART 4: Add constraints
-- ============================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_player_configs_one_default_per_user
ON player_configs(user_id)
WHERE is_default = TRUE;

-- ============================================================
-- Verification
-- ============================================================

DO $$
DECLARE
    migrated_count INTEGER;
    prefs_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO migrated_count FROM player_configs WHERE description = 'Migrated from user_preferences';
    SELECT COUNT(*) INTO prefs_count FROM user_preferences;

    RAISE NOTICE '============================================';
    RAISE NOTICE 'Migration completed!';
    RAISE NOTICE 'User preferences rows: %', prefs_count;
    RAISE NOTICE 'Player configs created: %', migrated_count;
    RAISE NOTICE '============================================';
END $$;

COMMIT;

-- Verify columns removed from user_preferences
SELECT 'user_preferences columns:' AS info;
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'user_preferences' ORDER BY ordinal_position;

-- Verify player_configs structure
SELECT 'player_configs columns:' AS info;
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'player_configs' ORDER BY ordinal_position;

-- Sample data
SELECT 'Sample migrated data:' AS info;
SELECT pc.user_id, pc.name, pc.autoplay, pc.loop, pc.muted, pc.show_controls, pc.is_default
FROM player_configs pc
WHERE pc.description = 'Migrated from user_preferences'
LIMIT 5;
