# Changelog

## 2026-03-01 - Foundation System Additions (Backward Compatible)

### New API Endpoints
- `GET /v1/stacks`
- `GET /v1/stacks/{stack_id}`
- `POST /v1/servers/{server_id}/provision-plan`
- `GET /v1/provision-plans/{plan_id}`
- `POST /v1/servers/{server_id}/preflight`
- `POST /v1/servers/{server_id}/preflight/results`
- `GET /v1/templates`
- `GET /v1/templates/{template_id}`
- `POST /v1/validate/docker-compose`
- `POST /v1/validate/nginx`
- `GET /v1/servers/{server_id}/logs`
- `GET /v1/servers/{server_id}/metrics`
- `GET /v1/servers/{server_id}/timeline`
- `GET /v1/servers/{server_id}/troubleshooting-packet`
- `POST /v1/agent/self-check`
- `GET /v1/agent/install-config`

### New Database Tables
- `stacks`
- `templates`
- `provision_plans`
- `preflight_runs`
- `server_metrics`
- `server_logs`
- `server_events`
- `agent_capabilities`
- `server_heartbeats`

### Observability Enhancements
- Structured log ingestion with `service`, `fingerprint`, and `tags`.
- Raw metrics mirrored to `server_metrics` for bucketed history queries.
- Docker events captured into `server_events` timeline.

### Agent / Installer Enhancements
- Installer supports `--name`, `--units`, `--interval`, `--tags`, `--image`.
- Installer fetches preferred image from backend via `/v1/agent/install-config` (fallback to default image).
- Agent sends periodic self-check capabilities to `/v1/agent/self-check`.

### Backward Compatibility
- Existing endpoints and response shapes from current Postman flow remain available.
- `GET /v1/servers/{server_id}` only adds optional fields: `agent_capabilities`, `last_heartbeat_at`, `heartbeat_status`.

### New Env Vars
- `AGENT_DEFAULT_IMAGE` (default: `bsign/devops-agent:latest`)
