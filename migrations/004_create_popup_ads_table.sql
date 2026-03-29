CREATE TABLE IF NOT EXISTS popup_ads (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL,
    label TEXT NOT NULL,
    value TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    max_triggers_per_session INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_popup_ads_user_id ON popup_ads(user_id);
CREATE INDEX IF NOT EXISTS idx_popup_ads_user_active ON popup_ads(user_id, is_active);
