-- Migration: Create player_configs table
-- Created: 2026-03-19
-- Description: Creates the player_configs table for storing multiple player configurations per user

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

-- Index for user_id to optimize queries by user
CREATE INDEX IF NOT EXISTS idx_player_configs_user_id ON player_configs(user_id);

-- Index for is_default to optimize default config lookups
CREATE INDEX IF NOT EXISTS idx_player_configs_is_default ON player_configs(is_default);

-- Composite index for user + is_default (common query pattern)
CREATE INDEX IF NOT EXISTS idx_player_configs_user_default ON player_configs(user_id, is_default);

-- Trigger function to update updated_at and version on row update
CREATE OR REPLACE FUNCTION update_player_configs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at and version
CREATE OR REPLACE TRIGGER trg_update_player_configs
BEFORE UPDATE ON player_configs
FOR EACH ROW
EXECUTE FUNCTION update_player_configs_updated_at();

-- Comments for documentation
COMMENT ON TABLE player_configs IS 'Stores multiple player configurations per user for video playback settings';
COMMENT ON COLUMN player_configs.id IS 'Unique identifier for the player config (UUID)';
COMMENT ON COLUMN player_configs.user_id IS 'Reference to the user who owns this config';
COMMENT ON COLUMN player_configs.name IS 'Human-readable name for the configuration';
COMMENT ON COLUMN player_configs.description IS 'Optional description of the configuration';
COMMENT ON COLUMN player_configs.autoplay IS 'Whether videos should autoplay';
COMMENT ON COLUMN player_configs.loop IS 'Whether videos should loop on end';
COMMENT ON COLUMN player_configs.muted IS 'Whether videos should start muted';
COMMENT ON COLUMN player_configs.show_controls IS 'Whether to show player controls';
COMMENT ON COLUMN player_configs.pip IS 'Whether Picture-in-Picture is enabled';
COMMENT ON COLUMN player_configs.airplay IS 'Whether AirPlay is enabled';
COMMENT ON COLUMN player_configs.chromecast IS 'Whether Chromecast is enabled';
COMMENT ON COLUMN player_configs.is_active IS 'Whether this config is active';
COMMENT ON COLUMN player_configs.is_default IS 'Whether this is the default config for new videos';
COMMENT ON COLUMN player_configs.version IS 'Optimistic locking version number';
