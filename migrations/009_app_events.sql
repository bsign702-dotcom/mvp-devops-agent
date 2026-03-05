-- App Keys: per-server API keys for sending custom application events
CREATE TABLE IF NOT EXISTS app_keys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        text NOT NULL,
    key_hash    text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

CREATE INDEX IF NOT EXISTS idx_app_keys_server_id ON app_keys (server_id);
CREATE INDEX IF NOT EXISTS idx_app_keys_key_hash ON app_keys (key_hash) WHERE revoked_at IS NULL;

-- Application events sent via app keys
CREATE TABLE IF NOT EXISTS app_events (
    id          bigserial PRIMARY KEY,
    server_id   uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source      text NOT NULL,
    event       text NOT NULL,
    severity    text NOT NULL DEFAULT 'info',
    meta        jsonb NOT NULL DEFAULT '{}',
    ip          text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_app_events_server_created ON app_events (server_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_events_event ON app_events (event);
CREATE INDEX IF NOT EXISTS idx_app_events_source ON app_events (source);
CREATE INDEX IF NOT EXISTS idx_app_events_user_created ON app_events (user_id, created_at DESC);

-- Alert rules for application events (threshold-based)
CREATE TABLE IF NOT EXISTS event_alert_rules (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id   uuid REFERENCES servers(id) ON DELETE CASCADE,
    name        text NOT NULL,
    event       text NOT NULL,
    source      text,
    severity_filter text,
    threshold   int NOT NULL DEFAULT 10,
    window_seconds int NOT NULL DEFAULT 300,
    is_enabled  boolean NOT NULL DEFAULT TRUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_event_alert_rules_user ON event_alert_rules (user_id) WHERE is_enabled = TRUE;
