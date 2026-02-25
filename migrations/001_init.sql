CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS servers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    agent_token_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'offline')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_servers_status ON servers (status);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen_at_desc ON servers (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS metrics (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL,
    cpu_percent real,
    ram_percent real,
    disk_percent real,
    load1 real,
    load5 real,
    load15 real,
    net_bytes_sent bigint,
    net_bytes_recv bigint
);

CREATE INDEX IF NOT EXISTS idx_metrics_server_id_ts_desc ON metrics (server_id, ts DESC);

CREATE TABLE IF NOT EXISTS logs (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL,
    source text CHECK (source IN ('systemd', 'docker', 'nginx', 'app')),
    level text CHECK (level IN ('info', 'warn', 'error')),
    message text
);

CREATE INDEX IF NOT EXISTS idx_logs_server_id_ts_desc ON logs (server_id, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL DEFAULT now(),
    type text NOT NULL CHECK (type IN ('cpu_high', 'ram_high', 'disk_high', 'service_restart', 'agent_offline')),
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    is_resolved boolean NOT NULL DEFAULT false,
    resolved_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_server_id_ts_desc ON alerts (server_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_is_resolved ON alerts (is_resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type);
