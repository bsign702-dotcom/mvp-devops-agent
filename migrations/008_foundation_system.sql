CREATE TABLE IF NOT EXISTS stacks (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL,
    required_inputs jsonb NOT NULL DEFAULT '[]'::jsonb,
    steps jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_agent_capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS templates (
    id text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    description text NOT NULL,
    compose text NOT NULL DEFAULT '',
    nginx_conf text NOT NULL DEFAULT '',
    env_template text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS provision_plans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    stack_id text NOT NULL REFERENCES stacks(id) ON DELETE RESTRICT,
    inputs jsonb NOT NULL DEFAULT '{}'::jsonb,
    files jsonb NOT NULL DEFAULT '[]'::jsonb,
    commands jsonb NOT NULL DEFAULT '[]'::jsonb,
    notes jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_provision_plans_user_server_created_desc
    ON provision_plans (user_id, server_id, created_at DESC);

CREATE TABLE IF NOT EXISTS preflight_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    checklist jsonb NOT NULL DEFAULT '[]'::jsonb,
    submitted_results jsonb NOT NULL DEFAULT '{}'::jsonb,
    missing_items jsonb NOT NULL DEFAULT '[]'::jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'incomplete', 'ready')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_preflight_runs_user_server_created_desc
    ON preflight_runs (user_id, server_id, created_at DESC);

CREATE TABLE IF NOT EXISTS server_metrics (
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
    net_bytes_recv bigint,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_server_metrics_server_ts_desc ON server_metrics (server_id, ts DESC);

CREATE TABLE IF NOT EXISTS server_logs (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL,
    source text NOT NULL,
    service text,
    level text NOT NULL,
    message text NOT NULL,
    fingerprint text NOT NULL,
    tags jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_server_logs_server_ts_desc ON server_logs (server_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_server_logs_server_source_level_ts_desc ON server_logs (server_id, source, level, ts DESC);
CREATE INDEX IF NOT EXISTS idx_server_logs_fingerprint ON server_logs (fingerprint);
CREATE INDEX IF NOT EXISTS idx_server_logs_service ON server_logs (service);

CREATE TABLE IF NOT EXISTS server_events (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL,
    event_type text NOT NULL,
    source text NOT NULL,
    service text,
    title text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_server_events_server_ts_desc ON server_events (server_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_server_events_server_event_type_ts_desc ON server_events (server_id, event_type, ts DESC);

CREATE TABLE IF NOT EXISTS agent_capabilities (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL UNIQUE REFERENCES servers(id) ON DELETE CASCADE,
    supports_docker boolean NOT NULL DEFAULT false,
    supports_systemd boolean NOT NULL DEFAULT false,
    supports_journalctl boolean NOT NULL DEFAULT false,
    supports_nginx_logs boolean NOT NULL DEFAULT false,
    nginx_paths jsonb NOT NULL DEFAULT '[]'::jsonb,
    docker_version text,
    systemd_version text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS server_heartbeats (
    id bigserial PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL DEFAULT 'ingest',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_server_heartbeats_server_ts_desc ON server_heartbeats (server_id, ts DESC);

INSERT INTO stacks (id, name, description, required_inputs, steps, required_agent_capabilities)
VALUES
(
    'docker-nginx-basic',
    'Docker + Nginx Basic',
    'Opinionated baseline for web apps behind nginx reverse proxy with TLS and firewall.',
    '["domain","email","app_port"]'::jsonb,
    '["install docker", "write docker-compose", "write nginx config", "enable site", "certbot", "ufw", "verify"]'::jsonb,
    '["docker_logs", "nginx_logs", "systemd_logs"]'::jsonb
),
(
    'python-api-postgres',
    'Python API + Postgres',
    'Python API with PostgreSQL, reverse proxy, healthchecks, and backup-ready baseline.',
    '["domain","email","repo_url","app_port","db_password"]'::jsonb,
    '["prepare env", "compose up", "nginx config", "certbot", "verify"]'::jsonb,
    '["docker_logs", "systemd_logs"]'::jsonb
),
(
    'node-app-redis',
    'Node App + Redis',
    'Node runtime with Redis cache, nginx reverse proxy, and hardened defaults.',
    '["domain","email","repo_url","app_port"]'::jsonb,
    '["prepare env", "compose up", "nginx config", "certbot", "verify"]'::jsonb,
    '["docker_logs", "nginx_logs"]'::jsonb
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO templates (id, name, kind, description, compose, nginx_conf, env_template, metadata)
VALUES
(
    'fastapi-prod',
    'FastAPI Production',
    'fastapi',
    'FastAPI app + Postgres + nginx reverse proxy.',
    'services:\n  app:\n    image: ghcr.io/example/fastapi-app:1.0.0\n    restart: unless-stopped\n    environment:\n      - APP_ENV=production\n    healthcheck:\n      test: ["CMD", "curl", "-fsS", "http://localhost:8000/health"]\n      interval: 30s\n      timeout: 5s\n      retries: 5\n    ports:\n      - "8000:8000"\n  db:\n    image: postgres:16\n    restart: unless-stopped\n    healthcheck:\n      test: ["CMD-SHELL", "pg_isready -U postgres"]\n      interval: 30s\n      timeout: 5s\n      retries: 5\n',
    'server {\n  listen 80;\n  server_name {{domain}};\n  location / {\n    proxy_pass http://127.0.0.1:8000;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection "upgrade";\n    proxy_read_timeout 60s;\n    proxy_connect_timeout 10s;\n    proxy_send_timeout 60s;\n  }\n}\n',
    'APP_ENV=production\nDATABASE_URL=postgresql://postgres:{{db_password}}@db:5432/app\n',
    '{}'::jsonb
),
(
    'node-nextjs',
    'Node / Next.js',
    'node',
    'Node or Next.js deployment template with nginx reverse proxy.',
    'services:\n  app:\n    image: ghcr.io/example/node-app:1.0.0\n    restart: unless-stopped\n    healthcheck:\n      test: ["CMD", "curl", "-fsS", "http://localhost:3000/"]\n      interval: 30s\n      timeout: 5s\n      retries: 5\n    ports:\n      - "3000:3000"\n',
    'server {\n  listen 80;\n  server_name {{domain}};\n  location / {\n    proxy_pass http://127.0.0.1:3000;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection "upgrade";\n  }\n}\n',
    'NODE_ENV=production\nPORT=3000\n',
    '{}'::jsonb
),
(
    'static-nginx',
    'Static Site (Nginx)',
    'static',
    'Static files served by nginx with TLS-ready config.',
    'services:\n  web:\n    image: nginx:1.27\n    restart: unless-stopped\n    ports:\n      - "8080:80"\n',
    'server {\n  listen 80;\n  server_name {{domain}};\n  root /var/www/html;\n  index index.html;\n  location / {\n    try_files $uri $uri/ =404;\n  }\n}\n',
    '# static site has no app env by default\n',
    '{}'::jsonb
)
ON CONFLICT (id) DO NOTHING;
