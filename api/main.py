from __future__ import annotations

import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from .alerts import (
    evaluate_metric_alerts,
    infer_log_level,
    is_service_restart_line,
    maybe_create_service_restart_alert,
    resolve_alert_type,
)
from .db import ensure_migrated, get_engine, wait_for_db
from .errors import APIError, install_error_handlers
from .models import (
    AgentSelfCheckRequest,
    AgentSelfCheckResponse,
    AlertItem,
    ChatAskResponse,
    ChatMessageCreateRequest,
    ChatMessageItem,
    ChatSessionCreateRequest,
    ChatSessionItem,
    ComposeLintRequest,
    LintResponse,
    LogSearchResponse,
    MetricsHistoryResponse,
    NginxLintRequest,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    PreflightCreateRequest,
    PreflightCreateResponse,
    PreflightResultsRequest,
    PreflightResultsResponse,
    ProjectTemplateDetail,
    ProjectTemplateItem,
    ProvisionPlanCreateRequest,
    ProvisionPlanResponse,
    StackDetailResponse,
    StackItem,
    MetricSummary,
    NotificationSettingItem,
    NotificationSettingUpsertRequest,
    NotificationTestEmailRequest,
    NotificationTestEmailResponse,
    ServerCreateRequest,
    ServerCreateResponse,
    ServerDeleteResponse,
    ServerDetailResponse,
    ServerLogItem,
    ServerListItem,
    TimelineResponse,
    TroubleshootingPacketResponse,
    UptimeCheckItem,
    UptimeMonitorCreateRequest,
    UptimeMonitorDeleteResponse,
    UptimeMonitorItem,
    UserMeResponse,
)
from .rate_limit import InMemoryRateLimiter
from .scheduler import start_scheduler, stop_scheduler
from .security import generate_agent_token, hash_agent_token
from .services.auth_service import AuthenticatedUser, require_authenticated_user
from .services.admin_notify_service import notify_server_created
from .services.chat_service import (
    ask_chat_assistant as svc_ask_chat_assistant,
    create_chat_session as svc_create_chat_session,
    list_chat_messages as svc_list_chat_messages,
    list_chat_sessions as svc_list_chat_sessions,
)
from .services.platform_service import (
    build_log_fingerprint,
    build_troubleshooting_packet,
    create_preflight_run,
    create_provision_plan,
    get_agent_install_config,
    get_metrics_history,
    get_provision_plan,
    get_stack,
    get_template,
    get_timeline,
    lint_compose_yaml,
    lint_nginx_conf,
    list_stacks,
    list_templates,
    search_server_logs,
    submit_preflight_results,
    upsert_agent_self_check,
)
from .services.notification_service import (
    list_notification_settings as svc_list_notification_settings,
    send_test_email as svc_send_test_email,
    upsert_notification_setting as svc_upsert_notification_setting,
)
from .settings import get_settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "asctime",
            }:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, get_settings().json_log_level.upper(), logging.INFO))


configure_logging()
logger = logging.getLogger(__name__)
settings = get_settings()
rate_limiter = InMemoryRateLimiter()
app = FastAPI(title="AI DevOps Monitor API", version="0.1.0")
install_error_handlers(app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

INSTALL_SH_PATH = Path(__file__).resolve().parent.parent / "scripts" / "install.sh"


@app.middleware("http")
async def request_logging_and_ip_rate_limit(request: Request, call_next):
    start = time.perf_counter()
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )
    try:
        rate_limiter.check(f"ip:{client_ip}", settings.ip_rate_limit_per_minute)
        response = await call_next(request)
        return response
    finally:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "http_request",
            extra={
                "event": "http_request",
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "duration_ms": duration_ms,
            },
        )


@app.on_event("startup")
async def _startup() -> None:
    wait_for_db()
    ensure_migrated()
    start_scheduler()


@app.on_event("shutdown")
async def _shutdown() -> None:
    stop_scheduler()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/install.sh", response_class=PlainTextResponse)
def get_install_script() -> PlainTextResponse:
    if not INSTALL_SH_PATH.exists():
        raise APIError(code="not_found", message="install.sh not found", status_code=404)
    return PlainTextResponse(
        INSTALL_SH_PATH.read_text(encoding="utf-8"),
        media_type="text/x-shellscript; charset=utf-8",
    )


@app.get("/v1/auth/me", response_model=UserMeResponse)
def auth_me(current_user: AuthenticatedUser = Depends(require_authenticated_user)) -> UserMeResponse:
    return UserMeResponse(
        user_id=current_user.local_user_id,
        supabase_user_id=current_user.supabase_user_id,
        email=current_user.email,
        full_name=current_user.full_name,
        metadata=current_user.metadata,
    )


@app.get("/v1/stacks", response_model=list[StackItem])
def get_stacks(_: AuthenticatedUser = Depends(require_authenticated_user)) -> list[StackItem]:
    return [StackItem(**row) for row in list_stacks()]


@app.get("/v1/stacks/{stack_id}", response_model=StackDetailResponse)
def get_stack_by_id(
    stack_id: str,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> StackDetailResponse:
    return StackDetailResponse(**get_stack(stack_id))


@app.post("/v1/servers/{server_id}/provision-plan", response_model=ProvisionPlanResponse)
def create_server_provision_plan(
    server_id: UUID,
    payload: ProvisionPlanCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ProvisionPlanResponse:
    row = create_provision_plan(
        user_id=current_user.local_user_id,
        server_id=server_id,
        stack_id=payload.stack_id,
        inputs=payload.inputs,
    )
    return ProvisionPlanResponse(**row)


@app.get("/v1/provision-plans/{plan_id}", response_model=ProvisionPlanResponse)
def get_server_provision_plan(
    plan_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ProvisionPlanResponse:
    row = get_provision_plan(user_id=current_user.local_user_id, plan_id=plan_id)
    return ProvisionPlanResponse(**row)


@app.post("/v1/servers/{server_id}/preflight", response_model=PreflightCreateResponse)
def create_server_preflight(
    server_id: UUID,
    payload: PreflightCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> PreflightCreateResponse:
    row = create_preflight_run(
        user_id=current_user.local_user_id,
        server_id=server_id,
        stack_id=payload.stack_id,
        inputs=payload.inputs,
    )
    return PreflightCreateResponse(**row)


@app.post("/v1/servers/{server_id}/preflight/results", response_model=PreflightResultsResponse)
def submit_server_preflight_results(
    server_id: UUID,
    payload: PreflightResultsRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> PreflightResultsResponse:
    row = submit_preflight_results(
        user_id=current_user.local_user_id,
        server_id=server_id,
        run_id=payload.run_id,
        results=payload.results,
    )
    return PreflightResultsResponse(**row)


@app.get("/v1/templates", response_model=list[ProjectTemplateItem])
def get_project_templates(
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ProjectTemplateItem]:
    return [ProjectTemplateItem(**row) for row in list_templates()]


@app.get("/v1/templates/{template_id}", response_model=ProjectTemplateDetail)
def get_project_template(
    template_id: str,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> ProjectTemplateDetail:
    return ProjectTemplateDetail(**get_template(template_id))


@app.post("/v1/validate/docker-compose", response_model=LintResponse)
def validate_compose(
    payload: ComposeLintRequest,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> LintResponse:
    return LintResponse(**lint_compose_yaml(payload.yaml))


@app.post("/v1/validate/nginx", response_model=LintResponse)
def validate_nginx(
    payload: NginxLintRequest,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> LintResponse:
    return LintResponse(**lint_nginx_conf(payload.conf))


@app.get("/v1/servers/{server_id}/logs", response_model=LogSearchResponse)
def get_server_logs(
    server_id: UUID,
    source: str | None = Query(default=None),
    level: str | None = Query(default=None),
    q: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> LogSearchResponse:
    row = search_server_logs(
        user_id=current_user.local_user_id,
        server_id=server_id,
        source=source,
        level=level,
        query=q,
        since=since,
        until=until,
        limit=limit,
    )
    return LogSearchResponse(**row)


@app.get("/v1/servers/{server_id}/metrics", response_model=MetricsHistoryResponse)
def get_server_metrics_history(
    server_id: UUID,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    bucket: str = Query(default="5m"),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> MetricsHistoryResponse:
    row = get_metrics_history(
        user_id=current_user.local_user_id,
        server_id=server_id,
        since=since,
        until=until,
        bucket=bucket,
    )
    return MetricsHistoryResponse(**row)


@app.get("/v1/servers/{server_id}/timeline", response_model=TimelineResponse)
def get_server_timeline(
    server_id: UUID,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> TimelineResponse:
    row = get_timeline(
        user_id=current_user.local_user_id,
        server_id=server_id,
        since=since,
        until=until,
    )
    return TimelineResponse(**row)


@app.get("/v1/servers/{server_id}/troubleshooting-packet", response_model=TroubleshootingPacketResponse)
def get_server_troubleshooting_packet(
    server_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> TroubleshootingPacketResponse:
    return TroubleshootingPacketResponse(
        **build_troubleshooting_packet(user_id=current_user.local_user_id, server_id=server_id)
    )


@app.post("/v1/agent/self-check", response_model=AgentSelfCheckResponse)
def agent_self_check(payload: AgentSelfCheckRequest, request: Request) -> AgentSelfCheckResponse:
    raw_token = _extract_bearer_token(request)
    token_hash = hash_agent_token(raw_token, settings.agent_token_pepper)
    rate_limiter.check(f"agent:{token_hash}", settings.agent_rate_limit_per_minute)
    row = upsert_agent_self_check(token_hash=token_hash, payload=payload.model_dump())
    return AgentSelfCheckResponse(**row)


@app.get("/v1/agent/install-config")
def agent_install_config(request: Request) -> dict[str, Any]:
    raw_token = _extract_bearer_token(request)
    token_hash = hash_agent_token(raw_token, settings.agent_token_pepper)
    rate_limiter.check(f"agent:{token_hash}", settings.agent_rate_limit_per_minute)
    return get_agent_install_config(
        token_hash=token_hash,
        default_image=settings.agent_default_image,
    )


@app.post("/v1/chat/sessions", response_model=ChatSessionItem)
def create_chat_session(
    payload: ChatSessionCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ChatSessionItem:
    row = svc_create_chat_session(
        user_id=current_user.local_user_id,
        server_id=payload.server_id,
        title=payload.title,
    )
    return ChatSessionItem(**row)


@app.get("/v1/chat/sessions", response_model=list[ChatSessionItem])
def list_chat_sessions(
    server_id: UUID | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ChatSessionItem]:
    rows = svc_list_chat_sessions(user_id=current_user.local_user_id, server_id=server_id)
    return [ChatSessionItem(**row) for row in rows]


@app.get("/v1/chat/sessions/{session_id}/messages", response_model=list[ChatMessageItem])
def list_chat_session_messages(
    session_id: UUID,
    limit: int = Query(default=200, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ChatMessageItem]:
    rows = svc_list_chat_messages(
        user_id=current_user.local_user_id,
        session_id=session_id,
        limit=limit,
    )
    return [ChatMessageItem(**row) for row in rows]


@app.post("/v1/chat/sessions/{session_id}/messages", response_model=ChatAskResponse)
def send_chat_session_message(
    session_id: UUID,
    payload: ChatMessageCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ChatAskResponse:
    row = svc_ask_chat_assistant(
        user_id=current_user.local_user_id,
        session_id=session_id,
        user_message=payload.message,
    )
    return ChatAskResponse(**row)


@app.post("/v1/servers", response_model=ServerCreateResponse)
def create_server(
    payload: ServerCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerCreateResponse:
    raw_token = generate_agent_token()
    token_hash = hash_agent_token(raw_token, settings.agent_token_pepper)

    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO servers (user_id, name, agent_token_hash, status, metadata)
                VALUES (
                    :user_id,
                    :name,
                    :agent_token_hash,
                    'pending',
                    CAST(:metadata AS jsonb)
                )
                RETURNING id, name
                """
            ),
            {
                "user_id": str(current_user.local_user_id),
                "name": payload.name,
                "agent_token_hash": token_hash,
                "metadata": json.dumps(
                    {"agent_image": settings.agent_default_image},
                    separators=(",", ":"),
                ),
            },
        ).mappings().one()

    install_command = (
        f"curl -fsSL {settings.app_public_install_sh_url} | sudo bash -s -- "
        f"--token \"{raw_token}\" --api \"{settings.api_base_url}\""
    )
    try:
        notify_server_created(
            actor_email=current_user.email,
            actor_full_name=current_user.full_name,
            server_id=row["id"],
            server_name=row["name"],
        )
    except Exception:
        logger.exception(
            "admin_notify_server_created_failed",
            extra={
                "event": "admin_notify_server_created_failed",
                "server_id": str(row["id"]),
                "server_name": row["name"],
                "user_id": str(current_user.local_user_id),
                "email": current_user.email,
            },
        )
    return ServerCreateResponse(
        server_id=row["id"],
        name=row["name"],
        agent_token=raw_token,
        install_command=install_command,
    )


@app.get("/v1/servers", response_model=list[ServerListItem])
def list_servers(current_user: AuthenticatedUser = Depends(require_authenticated_user)) -> list[ServerListItem]:
    rows = []
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id AS server_id, name, status, last_seen_at, created_at
                FROM servers
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                """
            ),
            {"user_id": str(current_user.local_user_id)},
        ).mappings().all()
    return [ServerListItem(**dict(row)) for row in rows]


@app.get("/v1/servers/{server_id}", response_model=ServerDetailResponse)
def get_server(
    server_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerDetailResponse:
    with get_engine().connect() as conn:
        server = conn.execute(
            text(
                """
                SELECT id AS server_id, name, status, created_at, last_seen_at, metadata
                FROM servers
                WHERE id = :server_id
                  AND user_id = :user_id
                """
            ),
            {"server_id": str(server_id), "user_id": str(current_user.local_user_id)},
        ).mappings().first()
        if not server:
            raise APIError(code="not_found", message="Server not found", status_code=404)

        metric_row = conn.execute(
            text(
                """
                SELECT ts, cpu_percent, ram_percent, disk_percent, load1, load5, load15,
                       net_bytes_sent, net_bytes_recv
                FROM metrics
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 1
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

        alert_rows = conn.execute(
            text(
                """
                SELECT id, server_id, uptime_monitor_id, ts, type, severity, title, details, is_resolved, resolved_at
                FROM alerts
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 20
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        log_rows = conn.execute(
            text(
                """
                SELECT ts, source, level, message
                FROM logs
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 120
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        cap_row = conn.execute(
            text(
                """
                SELECT supports_docker, supports_systemd, supports_journalctl, supports_nginx_logs,
                       nginx_paths, docker_version, systemd_version, metadata, updated_at
                FROM agent_capabilities
                WHERE server_id = :server_id
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

        hb_row = conn.execute(
            text(
                """
                SELECT ts
                FROM server_heartbeats
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 1
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

    metadata = server.get("metadata") or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    host_meta = metadata.get("host") if isinstance(metadata, dict) else {}
    if not isinstance(host_meta, dict):
        host_meta = {}
    ip_addresses = host_meta.get("ip_addresses") if isinstance(host_meta.get("ip_addresses"), list) else []
    ip_addresses = [str(ip).strip() for ip in ip_addresses if str(ip).strip()]
    domains = host_meta.get("domains") if isinstance(host_meta.get("domains"), list) else []
    domains = [str(domain).strip() for domain in domains if str(domain).strip()]
    primary_ip = host_meta.get("primary_ip")
    if primary_ip is not None:
        primary_ip = str(primary_ip).strip() or None

    docker_containers = metadata.get("docker_containers") if isinstance(metadata, dict) else []
    if not isinstance(docker_containers, list):
        docker_containers = []

    recent_logs_rows = [dict(row) for row in reversed(log_rows)]
    log_sources: dict[str, int] = {}
    for row in recent_logs_rows:
        source = str(row.get("source") or "unknown")
        log_sources[source] = log_sources.get(source, 0) + 1

    capabilities = dict(cap_row) if cap_row else {}
    if capabilities:
        capabilities["nginx_paths"] = [
            str(x) for x in _normalize_json_field(capabilities.get("nginx_paths") or [])
        ]
        capabilities["metadata"] = _normalize_json_field(capabilities.get("metadata") or {})

    last_heartbeat_at = hb_row["ts"] if hb_row else None
    heartbeat_status = None
    if last_heartbeat_at is not None:
        heartbeat_status = (
            "stale"
            if (datetime.now(timezone.utc) - last_heartbeat_at).total_seconds() > settings.offline_after_seconds
            else "ok"
        )

    return ServerDetailResponse(
        server_id=server["server_id"],
        name=server["name"],
        status=server["status"],
        created_at=server["created_at"],
        last_seen_at=server["last_seen_at"],
        metadata=metadata,
        ip_addresses=ip_addresses,
        domains=domains,
        primary_ip=primary_ip,
        docker_containers=docker_containers,
        log_sources=log_sources,
        recent_logs=[ServerLogItem(**row) for row in recent_logs_rows],
        agent_capabilities=capabilities,
        last_heartbeat_at=last_heartbeat_at,
        heartbeat_status=heartbeat_status,
        last_metrics=MetricSummary(**dict(metric_row)) if metric_row else None,
        alerts=[_row_to_alert_item(row) for row in alert_rows],
    )


@app.delete("/v1/servers/{server_id}", response_model=ServerDeleteResponse)
def delete_server(
    server_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerDeleteResponse:
    with get_engine().begin() as conn:
        deleted = conn.execute(
            text(
                """
                DELETE FROM servers
                WHERE id = :server_id
                  AND user_id = :user_id
                """
            ),
            {"server_id": str(server_id), "user_id": str(current_user.local_user_id)},
        )
        if not deleted.rowcount:
            raise APIError(code="not_found", message="Server not found", status_code=404)

    return ServerDeleteResponse(server_id=server_id)


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise APIError(code="unauthorized", message="Missing bearer token", status_code=401)
    token = auth_header[len("Bearer ") :].strip()
    if not token:
        raise APIError(code="unauthorized", message="Missing bearer token", status_code=401)
    return token


def _normalize_json_field(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _parse_log_service(source: str, message: str) -> str | None:
    msg = (message or "").strip()
    if not msg:
        return None
    match = re.match(r"^\[([^\]]+)\]", msg)
    if match:
        value = match.group(1).strip()
        if value:
            return value[:120]
    source_name = (source or "").strip().lower()
    if source_name in {"nginx", "docker", "systemd", "app"}:
        return source_name
    return None


def _parse_log_tags(source: str, level: str, message: str) -> list[str]:
    tags: list[str] = []
    src = (source or "").strip().lower()
    lvl = (level or "").strip().lower()
    msg = (message or "").lower()
    if src:
        tags.append(f"source:{src}")
    if lvl:
        tags.append(f"level:{lvl}")
    for token in ["timeout", "connection", "restart", "crash", "refused", "certificate", "ssl", "disk"]:
        if token in msg:
            tags.append(f"kw:{token}")
    deduped: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        deduped.append(tag)
    return deduped[:20]


def _row_to_alert_item(row: Any) -> AlertItem:
    data = dict(row)
    data["details"] = _normalize_json_field(data.get("details"))
    return AlertItem(**data)


def _row_to_uptime_monitor_item(row: Any) -> UptimeMonitorItem:
    return UptimeMonitorItem(**dict(row))


@app.post("/v1/uptime-monitors", response_model=UptimeMonitorItem)
def create_uptime_monitor(
    payload: UptimeMonitorCreateRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> UptimeMonitorItem:
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO uptime_monitors (
                    user_id, name, url, check_interval_sec, timeout_sec, expected_status
                ) VALUES (
                    :user_id, :name, :url, :check_interval_sec, :timeout_sec, :expected_status
                )
                RETURNING id, name, url, check_interval_sec, timeout_sec, expected_status,
                          last_status, last_response_time_ms, last_checked_at,
                          consecutive_failures, created_at
                """
            ),
            {
                "user_id": str(current_user.local_user_id),
                "name": payload.name.strip(),
                "url": str(payload.url),
                "check_interval_sec": payload.check_interval_sec,
                "timeout_sec": payload.timeout_sec,
                "expected_status": payload.expected_status,
            },
        ).mappings().one()
    return _row_to_uptime_monitor_item(row)


@app.get("/v1/uptime-monitors", response_model=list[UptimeMonitorItem])
def list_uptime_monitors(current_user: AuthenticatedUser = Depends(require_authenticated_user)) -> list[UptimeMonitorItem]:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, name, url, check_interval_sec, timeout_sec, expected_status,
                       last_status, last_response_time_ms, last_checked_at,
                       consecutive_failures, created_at
                FROM uptime_monitors
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                """
            ),
            {"user_id": str(current_user.local_user_id)},
        ).mappings().all()
    return [_row_to_uptime_monitor_item(row) for row in rows]


@app.get("/v1/uptime-monitors/{monitor_id}", response_model=UptimeMonitorItem)
def get_uptime_monitor(
    monitor_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> UptimeMonitorItem:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, name, url, check_interval_sec, timeout_sec, expected_status,
                       last_status, last_response_time_ms, last_checked_at,
                       consecutive_failures, created_at
                FROM uptime_monitors
                WHERE id = :monitor_id
                  AND user_id = :user_id
                """
            ),
            {"monitor_id": str(monitor_id), "user_id": str(current_user.local_user_id)},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Uptime monitor not found", status_code=404)
    return _row_to_uptime_monitor_item(row)


@app.delete("/v1/uptime-monitors/{monitor_id}", response_model=UptimeMonitorDeleteResponse)
def delete_uptime_monitor(
    monitor_id: UUID,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> UptimeMonitorDeleteResponse:
    with get_engine().begin() as conn:
        result = conn.execute(
            text("DELETE FROM uptime_monitors WHERE id = :monitor_id AND user_id = :user_id"),
            {"monitor_id": str(monitor_id), "user_id": str(current_user.local_user_id)},
        )
        if not result.rowcount:
            raise APIError(code="not_found", message="Uptime monitor not found", status_code=404)
    return UptimeMonitorDeleteResponse(monitor_id=monitor_id)


@app.get("/v1/uptime-monitors/{monitor_id}/checks", response_model=list[UptimeCheckItem])
def list_uptime_checks(
    monitor_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[UptimeCheckItem]:
    with get_engine().connect() as conn:
        monitor_exists = conn.execute(
            text("SELECT 1 FROM uptime_monitors WHERE id = :monitor_id AND user_id = :user_id"),
            {"monitor_id": str(monitor_id), "user_id": str(current_user.local_user_id)},
        ).first()
        if not monitor_exists:
            raise APIError(code="not_found", message="Uptime monitor not found", status_code=404)

        rows = conn.execute(
            text(
                """
                SELECT id, monitor_id, status, response_time_ms, status_code, error_message, checked_at
                FROM uptime_checks
                WHERE monitor_id = :monitor_id
                ORDER BY checked_at DESC
                LIMIT :limit
                """
            ),
            {"monitor_id": str(monitor_id), "limit": limit},
        ).mappings().all()
    return [UptimeCheckItem(**dict(row)) for row in rows]


@app.post("/v1/notifications/settings", response_model=NotificationSettingItem)
def upsert_notifications_settings(
    payload: NotificationSettingUpsertRequest,
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> NotificationSettingItem:
    with get_engine().begin() as conn:
        row = svc_upsert_notification_setting(conn, current_user.local_user_id, payload.model_dump())
    return NotificationSettingItem(**row)


@app.get("/v1/notifications/settings", response_model=list[NotificationSettingItem])
def get_notifications_settings(
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[NotificationSettingItem]:
    with get_engine().connect() as conn:
        rows = svc_list_notification_settings(conn, current_user.local_user_id)
    return [NotificationSettingItem(**row) for row in rows]


@app.post("/v1/notifications/test-email", response_model=NotificationTestEmailResponse)
def send_notifications_test_email(
    payload: NotificationTestEmailRequest,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> NotificationTestEmailResponse:
    svc_send_test_email(payload.email, settings.api_base_url)
    return NotificationTestEmailResponse(email=payload.email)


@app.post("/v1/ingest", response_model=IngestResponse)
def ingest(payload: IngestRequest, request: Request) -> IngestResponse:
    raw_token = _extract_bearer_token(request)
    token_hash = hash_agent_token(raw_token, settings.agent_token_pepper)
    rate_limiter.check(f"agent:{token_hash}", settings.agent_rate_limit_per_minute)
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    client_ip = forwarded_for or (request.client.host if request.client else "")

    with get_engine().begin() as conn:
        server = conn.execute(
            text(
                """
                SELECT id, name, user_id
                FROM servers
                WHERE agent_token_hash = :agent_token_hash
                LIMIT 1
                """
            ),
            {"agent_token_hash": token_hash},
        ).mappings().first()
        if not server:
            raise APIError(code="unauthorized", message="Invalid agent token", status_code=401)

        load_values = list(payload.metrics.loadavg or [])[:3]
        while len(load_values) < 3:
            load_values.append(None)

        conn.execute(
            text(
                """
                INSERT INTO metrics (
                    server_id, ts, cpu_percent, ram_percent, disk_percent,
                    load1, load5, load15, net_bytes_sent, net_bytes_recv
                ) VALUES (
                    :server_id, :ts, :cpu_percent, :ram_percent, :disk_percent,
                    :load1, :load5, :load15, :net_bytes_sent, :net_bytes_recv
                )
                """
            ),
            {
                "server_id": str(server["id"]),
                "ts": payload.ts,
                "cpu_percent": payload.metrics.cpu_percent,
                "ram_percent": payload.metrics.ram_percent,
                "disk_percent": payload.metrics.disk_percent,
                "load1": load_values[0],
                "load5": load_values[1],
                "load15": load_values[2],
                "net_bytes_sent": payload.metrics.net_bytes_sent,
                "net_bytes_recv": payload.metrics.net_bytes_recv,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO server_metrics (
                    server_id, ts, cpu_percent, ram_percent, disk_percent,
                    load1, load5, load15, net_bytes_sent, net_bytes_recv
                ) VALUES (
                    :server_id, :ts, :cpu_percent, :ram_percent, :disk_percent,
                    :load1, :load5, :load15, :net_bytes_sent, :net_bytes_recv
                )
                """
            ),
            {
                "server_id": str(server["id"]),
                "ts": payload.ts,
                "cpu_percent": payload.metrics.cpu_percent,
                "ram_percent": payload.metrics.ram_percent,
                "disk_percent": payload.metrics.disk_percent,
                "load1": load_values[0],
                "load5": load_values[1],
                "load15": load_values[2],
                "net_bytes_sent": payload.metrics.net_bytes_sent,
                "net_bytes_recv": payload.metrics.net_bytes_recv,
            },
        )

        host_meta = payload.host.model_dump(exclude_none=True)
        host_ips = host_meta.get("ip_addresses")
        if not isinstance(host_ips, list):
            host_ips = []
        host_ips = [str(ip).strip() for ip in host_ips if str(ip).strip()]
        if client_ip and client_ip not in host_ips:
            host_ips.append(client_ip)
        if host_ips:
            host_meta["ip_addresses"] = host_ips
        if not host_meta.get("primary_ip") and host_ips:
            host_meta["primary_ip"] = host_ips[0]
        if client_ip:
            host_meta["agent_client_ip"] = client_ip

        metadata_patch = {
            "host": host_meta,
            "docker_container_count": len(payload.docker.containers or []),
            "docker_containers": [
                {
                    "id": container.id,
                    "image": container.image,
                    "name": container.name,
                    "status": container.status,
                }
                for container in (payload.docker.containers or [])[:30]
            ],
            "docker_event_count": len(payload.docker.events or []),
            "last_ingest_ts": payload.ts.isoformat(),
        }
        conn.execute(
            text(
                """
                UPDATE servers
                SET last_seen_at = now(),
                    status = 'connected',
                    metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:metadata_patch AS jsonb)
                WHERE id = :server_id
                """
            ),
            {"server_id": str(server["id"]), "metadata_patch": json.dumps(metadata_patch)},
        )
        conn.execute(
            text(
                """
                INSERT INTO server_heartbeats (server_id, ts, source, metadata)
                VALUES (:server_id, :ts, 'ingest', CAST(:metadata AS jsonb))
                """
            ),
            {
                "server_id": str(server["id"]),
                "ts": payload.ts,
                "metadata": json.dumps({"host": host_meta}, separators=(",", ":"), default=str),
            },
        )
        resolve_alert_type(conn, server["id"], "agent_offline")

        logs_inserted = 0
        systemd_inserted = 0
        nginx_inserted = 0
        docker_inserted = 0
        restart_lines: list[str] = []
        max_logs = 360
        max_systemd_logs = 180
        max_nginx_logs = 90
        max_docker_logs = 90
        for unit, lines in (payload.logs.systemd or {}).items():
            for line in lines:
                if logs_inserted >= max_logs or systemd_inserted >= max_systemd_logs:
                    break
                msg = f"[{unit}] {line}" if unit else line
                level = infer_log_level(msg)
                conn.execute(
                    text(
                        """
                        INSERT INTO logs (server_id, ts, source, level, message)
                        VALUES (:server_id, :ts, 'systemd', :level, :message)
                        """
                    ),
                    {
                        "server_id": str(server["id"]),
                        "ts": payload.ts,
                        "level": level,
                        "message": msg,
                    },
                )
                service_name = _parse_log_service("systemd", msg)
                conn.execute(
                    text(
                        """
                        INSERT INTO server_logs (
                            server_id, ts, source, service, level, message, fingerprint, tags
                        ) VALUES (
                            :server_id, :ts, :source, :service, :level, :message, :fingerprint, CAST(:tags AS jsonb)
                        )
                        """
                    ),
                    {
                        "server_id": str(server["id"]),
                        "ts": payload.ts,
                        "source": "systemd",
                        "service": service_name,
                        "level": level,
                        "message": msg,
                        "fingerprint": build_log_fingerprint("systemd", service_name, msg),
                        "tags": json.dumps(_parse_log_tags("systemd", level, msg), separators=(",", ":")),
                    },
                )
                logs_inserted += 1
                systemd_inserted += 1
                if is_service_restart_line(msg):
                    restart_lines.append(msg)
            if logs_inserted >= max_logs or systemd_inserted >= max_systemd_logs:
                break

        for line in (payload.logs.nginx or []):
            if logs_inserted >= max_logs or nginx_inserted >= max_nginx_logs:
                break
            msg = str(line).strip()
            if not msg:
                continue
            level = infer_log_level(msg)
            conn.execute(
                text(
                    """
                    INSERT INTO logs (server_id, ts, source, level, message)
                    VALUES (:server_id, :ts, 'nginx', :level, :message)
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "level": level,
                    "message": msg,
                },
            )
            service_name = _parse_log_service("nginx", msg)
            conn.execute(
                text(
                    """
                    INSERT INTO server_logs (
                        server_id, ts, source, service, level, message, fingerprint, tags
                    ) VALUES (
                        :server_id, :ts, :source, :service, :level, :message, :fingerprint, CAST(:tags AS jsonb)
                    )
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "source": "nginx",
                    "service": service_name,
                    "level": level,
                    "message": msg,
                    "fingerprint": build_log_fingerprint("nginx", service_name, msg),
                    "tags": json.dumps(_parse_log_tags("nginx", level, msg), separators=(",", ":")),
                },
            )
            logs_inserted += 1
            nginx_inserted += 1

        for line in (payload.logs.docker or []):
            if logs_inserted >= max_logs or docker_inserted >= max_docker_logs:
                break
            msg = str(line).strip()
            if not msg:
                continue
            level = infer_log_level(msg)
            conn.execute(
                text(
                    """
                    INSERT INTO logs (server_id, ts, source, level, message)
                    VALUES (:server_id, :ts, 'docker', :level, :message)
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "level": level,
                    "message": msg,
                },
            )
            service_name = _parse_log_service("docker", msg)
            conn.execute(
                text(
                    """
                    INSERT INTO server_logs (
                        server_id, ts, source, service, level, message, fingerprint, tags
                    ) VALUES (
                        :server_id, :ts, :source, :service, :level, :message, :fingerprint, CAST(:tags AS jsonb)
                    )
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "source": "docker",
                    "service": service_name,
                    "level": level,
                    "message": msg,
                    "fingerprint": build_log_fingerprint("docker", service_name, msg),
                    "tags": json.dumps(_parse_log_tags("docker", level, msg), separators=(",", ":")),
                },
            )
            logs_inserted += 1
            docker_inserted += 1

        event_limit = 40
        event_count = 0
        for event in (payload.docker.events or []):
            if (
                logs_inserted >= max_logs
                or event_count >= event_limit
                or docker_inserted >= max_docker_logs
            ):
                break
            action = "event"
            name = "container"
            event_payload: dict[str, Any]
            if isinstance(event, dict):
                action = event.get("Action") or event.get("action") or event.get("status") or "event"
                actor = event.get("Actor") if isinstance(event.get("Actor"), dict) else {}
                attrs = actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
                name = attrs.get("name") or event.get("from") or "container"
                msg = f"[event] {action} ({name})"
                event_payload = event
            else:
                msg = f"[event] {str(event)}"
                event_payload = {"raw": str(event)}
            level = infer_log_level(msg)
            conn.execute(
                text(
                    """
                    INSERT INTO logs (server_id, ts, source, level, message)
                    VALUES (:server_id, :ts, 'docker', :level, :message)
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "level": level,
                    "message": msg,
                },
            )
            service_name = _parse_log_service("docker", msg)
            conn.execute(
                text(
                    """
                    INSERT INTO server_logs (
                        server_id, ts, source, service, level, message, fingerprint, tags
                    ) VALUES (
                        :server_id, :ts, :source, :service, :level, :message, :fingerprint, CAST(:tags AS jsonb)
                    )
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "source": "docker",
                    "service": service_name,
                    "level": level,
                    "message": msg,
                    "fingerprint": build_log_fingerprint("docker", service_name, msg),
                    "tags": json.dumps(_parse_log_tags("docker", level, msg), separators=(",", ":")),
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO server_events (server_id, ts, event_type, source, service, title, payload)
                    VALUES (
                        :server_id, :ts, :event_type, :source, :service, :title, CAST(:payload AS jsonb)
                    )
                    """
                ),
                {
                    "server_id": str(server["id"]),
                    "ts": payload.ts,
                    "event_type": str(action),
                    "source": "docker",
                    "service": str(name),
                    "title": msg[:180],
                    "payload": json.dumps(event_payload, separators=(",", ":"), default=str),
                },
            )
            logs_inserted += 1
            event_count += 1
            docker_inserted += 1

        alerts_created = evaluate_metric_alerts(
            conn,
            server_id=server["id"],
            owner_user_id=server.get("user_id"),
            cpu_percent=payload.metrics.cpu_percent,
            ram_percent=payload.metrics.ram_percent,
            disk_percent=payload.metrics.disk_percent,
            dedupe_seconds=settings.alert_dedupe_seconds,
        )
        if restart_lines and maybe_create_service_restart_alert(
            conn,
            server_id=server["id"],
            matched_lines=restart_lines,
            dedupe_seconds=settings.alert_dedupe_seconds,
        ):
            alerts_created.append("service_restart")

    return IngestResponse(
        server_id=server["id"],
        alerts_created=alerts_created,
        logs_inserted=logs_inserted,
    )


@app.get("/v1/alerts", response_model=list[AlertItem])
def list_alerts(
    server_id: UUID | None = Query(default=None),
    uptime_monitor_id: UUID | None = Query(default=None),
    resolved: bool | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[AlertItem]:
    conditions: list[str] = []
    params: dict[str, Any] = {"user_id": str(current_user.local_user_id)}
    conditions.append("user_id = :user_id")
    if server_id is not None:
        conditions.append("server_id = :server_id")
        params["server_id"] = str(server_id)
    if uptime_monitor_id is not None:
        conditions.append("uptime_monitor_id = :uptime_monitor_id")
        params["uptime_monitor_id"] = str(uptime_monitor_id)
    if resolved is not None:
        conditions.append("is_resolved = :resolved")
        params["resolved"] = resolved

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT id, server_id, uptime_monitor_id, ts, type, severity, title, details, is_resolved, resolved_at
        FROM alerts
        {where_clause}
        ORDER BY ts DESC
        LIMIT 500
    """
    with get_engine().connect() as conn:
        rows = conn.execute(text(query), params).mappings().all()
    return [_row_to_alert_item(row) for row in rows]
