# AI DevOps Monitor (MVP)

FastAPI + PostgreSQL backend with a simple Python agent and one-command Docker installer.

## Features

- Supabase bearer auth with local `users` sync (multi-tenant ownership)
- Per-server agent token (stored as HMAC-SHA256 hash only)
- Metrics + logs ingestion
- Deterministic alerts + dedupe
- Uptime monitoring + SSL expiry checks
- Notification emails (alerts, daily report, admin events)
- DevOps troubleshooting chat (LLM suggest-only mode) with server context
- Docker Compose local dev (`api` + `postgres`)

## Project Structure

- `api/` FastAPI backend
- `migrations/001_init.sql` PostgreSQL schema
- `agent/` Python agent + Dockerfile
- `scripts/install.sh` one-command installer for target servers
- `docker-compose.yml` local dev stack

## Local Dev Run (Docker Compose)

1. Start the stack:

```bash
docker-compose up --build
```

2. Verify health:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

Notes:

- The API waits for PostgreSQL and auto-applies `migrations/001_init.sql` on startup if the `servers` table does not exist.
- Default local DB connection in compose is:
  - `postgresql+psycopg://devops:devops@postgres:5432/devops`

## Create a Server (Generate Agent Token + Install Command)

```bash
curl -sS -X POST http://localhost:8000/v1/servers \
  -H 'Content-Type: application/json' \
  -d '{"name":"My VPS"}' | jq
```

Response includes:

- `server_id`
- `agent_token` (shown once)
- `install_command`

## Run the Agent Locally (for testing)

Build the agent image and tag it to match the installer default:

```bash
docker build -t yoursaas/devops-agent:latest -f agent/Dockerfile .
```

Manual agent run example:

```bash
docker run --rm \
  -e AGENT_TOKEN='svr_live_...' \
  -e INGEST_URL='http://host.docker.internal:8000/v1/ingest' \
  -e INTERVAL_SEC='15' \
  -e SYSTEMD_UNITS='nginx,ssh' \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/log:/var/log:ro \
  yoursaas/devops-agent:latest
```

On Linux, replace `host.docker.internal` with your host IP or API hostname if needed.

## Installer Script Usage (`scripts/install.sh`)

```bash
curl -fsSL https://app.yoursaas.com/install.sh | sudo bash -s -- --token "<agent_token>" --api "https://api.yoursaas.com"
```

Local file usage:

```bash
sudo bash scripts/install.sh --token "<agent_token>" --api "http://localhost:8000"
```

Behavior:

- Requires root/sudo
- Installs Docker on Ubuntu/Debian (`docker.io`) if missing
- Replaces existing `devops-agent` container (idempotent)
- Prints recent logs and troubleshooting commands

## API Endpoints

- `GET /health`
- `GET /v1/auth/me`
- `POST /v1/servers`
- `GET /v1/servers`
- `GET /v1/servers/{server_id}`
- `DELETE /v1/servers/{server_id}`
- `POST /v1/ingest` (requires `Authorization: Bearer <agent_token>`)
- `GET /v1/alerts?server_id=<uuid>&resolved=<true|false>`
- `POST /v1/uptime-monitors`
- `GET /v1/uptime-monitors`
- `GET /v1/uptime-monitors/{monitor_id}`
- `GET /v1/uptime-monitors/{monitor_id}/checks`
- `DELETE /v1/uptime-monitors/{monitor_id}`
- `POST /v1/notifications/settings`
- `GET /v1/notifications/settings`
- `POST /v1/notifications/test-email`
- `POST /v1/chat/sessions`
- `GET /v1/chat/sessions`
- `GET /v1/chat/sessions/{session_id}/messages`
- `POST /v1/chat/sessions/{session_id}/messages`

`GET /v1/servers/{server_id}` now also includes:
- `ip_addresses`, `primary_ip`, `domains`
- `docker_containers`
- `log_sources` summary and `recent_logs` (systemd/nginx/docker)

## LLM Config

Set these env vars in `.env` / compose:

- `LLM_PROVIDER=openai` (or `mock`)
- `LLM_MODEL=gpt-4.1-mini` (or your preferred model)
- `OPENAI_API_KEY=...`
- `OPENAI_BASE_URL=https://api.openai.com/v1`
- `LLM_TIMEOUT_SEC=45`
- `LLM_SUGGEST_ONLY=true`

## Example Ingest Call (Manual)

```bash
curl -sS -X POST http://localhost:8000/v1/ingest \
  -H "Authorization: Bearer <agent_token>" \
  -H 'Content-Type: application/json' \
  -d '{
    "ts":"2026-01-01T00:00:00Z",
    "host":{"hostname":"demo","os":"Linux","os_release":"6.8","machine":"x86_64"},
    "metrics":{
      "cpu_percent":12.3,
      "ram_percent":55.1,
      "disk_percent":70.2,
      "loadavg":[0.12,0.22,0.30],
      "net_bytes_sent":123,
      "net_bytes_recv":456
    },
    "docker":{"containers":[],"events":[]},
    "logs":{"systemd":{"nginx":["Started nginx"],"ssh":["Accepted publickey"]}}
  }' | jq
```

## Troubleshooting Commands

Local stack:

```bash
docker-compose ps
docker-compose logs api --tail=200
docker-compose logs postgres --tail=200
```

Database shell:

```bash
docker-compose exec postgres psql -U devops -d devops
```

Useful SQL checks:

```sql
SELECT id, name, status, last_seen_at FROM servers ORDER BY created_at DESC;
SELECT server_id, ts, cpu_percent, ram_percent, disk_percent FROM metrics ORDER BY id DESC LIMIT 20;
SELECT server_id, type, severity, is_resolved, ts FROM alerts ORDER BY id DESC LIMIT 20;
```

If agent ingestion fails:

- Confirm the token is the one-time token returned by `POST /v1/servers`
- Check API logs for `401` or validation errors
- Confirm `INGEST_URL` points to `/v1/ingest`
- Confirm the target can reach the API hostname/port

## Security / MVP Notes

- API access is authenticated by Supabase bearer token for user endpoints
- Ingestion is protected by per-server bearer tokens
- Raw agent tokens are never stored in PostgreSQL (only HMAC-SHA256 hashes with server-side pepper)
- Rate limiting is in-memory (per-IP and per-agent-token-hash)
- LLM chat is suggest-only by default (no remote command execution)
