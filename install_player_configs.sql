-- Quick install script for player_configs table
-- Run this directly in your PostgreSQL database
-- Usage: psql -d video_db -f install_player_configs.sql

BEGIN;

-- Create player_configs table
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_player_configs_user_id ON player_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_player_configs_is_default ON player_configs(is_default);
CREATE INDEX IF NOT EXISTS idx_player_configs_user_default ON player_configs(user_id, is_default);

-- Trigger to auto-update updated_at and version
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

COMMIT;

-- Verify installation
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_name = 'player_configs'
ORDER BY ordinal_position;
