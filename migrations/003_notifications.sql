CREATE TABLE IF NOT EXISTS notification_settings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    is_enabled boolean NOT NULL DEFAULT true,
    cpu_threshold integer NOT NULL DEFAULT 80,
    disk_threshold integer NOT NULL DEFAULT 85,
    ram_threshold integer NOT NULL DEFAULT 85,
    offline_threshold_sec integer NOT NULL DEFAULT 120,
    daily_report_time_utc time NOT NULL DEFAULT '08:00',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_settings_enabled ON notification_settings (is_enabled);
CREATE INDEX IF NOT EXISTS idx_notification_settings_daily_time ON notification_settings (daily_report_time_utc);

CREATE TABLE IF NOT EXISTS notification_events (
    id bigserial PRIMARY KEY,
    key text NOT NULL UNIQUE,
    email text NOT NULL,
    alert_id bigint NULL REFERENCES alerts(id) ON DELETE SET NULL,
    event_type text NOT NULL CHECK (event_type IN ('ALERT_EMAIL', 'DAILY_REPORT')),
    sent_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status IN ('sent', 'failed')),
    error text NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_events_email_sent_at_desc ON notification_events (email, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_events_event_type ON notification_events (event_type);
