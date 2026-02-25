CREATE TABLE IF NOT EXISTS uptime_monitors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    url text NOT NULL,
    check_interval_sec integer NOT NULL DEFAULT 30,
    timeout_sec integer NOT NULL DEFAULT 10,
    expected_status integer NOT NULL DEFAULT 200,
    last_status text NOT NULL DEFAULT 'unknown' CHECK (last_status IN ('up', 'down', 'unknown')),
    last_response_time_ms integer,
    last_checked_at timestamptz,
    consecutive_failures integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_uptime_monitors_last_checked_at ON uptime_monitors (last_checked_at);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id bigserial PRIMARY KEY,
    monitor_id uuid NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('up', 'down')),
    response_time_ms integer,
    status_code integer,
    error_message text,
    checked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_uptime_checks_monitor_checked_at_desc ON uptime_checks (monitor_id, checked_at DESC);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS uptime_monitor_id uuid NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE;
ALTER TABLE alerts ALTER COLUMN server_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_uptime_monitor_id_ts_desc ON alerts (uptime_monitor_id, ts DESC);

ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_type_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_type_check CHECK (
    type IN (
        'cpu_high', 'ram_high', 'disk_high', 'service_restart', 'agent_offline',
        'UPTIME_DOWN', 'UPTIME_RECOVERED', 'SSL_EXPIRING'
    )
);
