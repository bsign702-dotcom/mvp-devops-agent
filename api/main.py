from __future__ import annotations

import json
import logging
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
    AlertItem,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    MetricSummary,
    NotificationSettingItem,
    NotificationSettingUpsertRequest,
    NotificationTestEmailRequest,
    NotificationTestEmailResponse,
    ServerCreateRequest,
    ServerCreateResponse,
    ServerDeleteResponse,
    ServerDetailResponse,
    ServerListItem,
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


@app.post("/v1/servers", response_model=ServerCreateResponse)
def create_server(
    payload: ServerCreateRequest,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerCreateResponse:
    raw_token = generate_agent_token()
    token_hash = hash_agent_token(raw_token, settings.agent_token_pepper)

    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO servers (name, agent_token_hash, status)
                VALUES (:name, :agent_token_hash, 'pending')
                RETURNING id, name
                """
            ),
            {"name": payload.name, "agent_token_hash": token_hash},
        ).mappings().one()

    install_command = (
        f"curl -fsSL {settings.app_public_install_sh_url} | sudo bash -s -- "
        f"--token \"{raw_token}\" --api \"{settings.api_base_url}\""
    )
    return ServerCreateResponse(
        server_id=row["id"],
        name=row["name"],
        agent_token=raw_token,
        install_command=install_command,
    )


@app.get("/v1/servers", response_model=list[ServerListItem])
def list_servers(_: AuthenticatedUser = Depends(require_authenticated_user)) -> list[ServerListItem]:
    rows = []
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id AS server_id, name, status, last_seen_at, created_at
                FROM servers
                ORDER BY created_at DESC
                """
            )
        ).mappings().all()
    return [ServerListItem(**dict(row)) for row in rows]


@app.get("/v1/servers/{server_id}", response_model=ServerDetailResponse)
def get_server(
    server_id: UUID,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerDetailResponse:
    with get_engine().connect() as conn:
        server = conn.execute(
            text(
                """
                SELECT id AS server_id, name, status, created_at, last_seen_at, metadata
                FROM servers
                WHERE id = :server_id
                """
            ),
            {"server_id": str(server_id)},
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

    metadata = server.get("metadata") or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    return ServerDetailResponse(
        server_id=server["server_id"],
        name=server["name"],
        status=server["status"],
        created_at=server["created_at"],
        last_seen_at=server["last_seen_at"],
        metadata=metadata,
        last_metrics=MetricSummary(**dict(metric_row)) if metric_row else None,
        alerts=[_row_to_alert_item(row) for row in alert_rows],
    )


@app.delete("/v1/servers/{server_id}", response_model=ServerDeleteResponse)
def delete_server(
    server_id: UUID,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> ServerDeleteResponse:
    with get_engine().begin() as conn:
        deleted = conn.execute(
            text(
                """
                DELETE FROM servers
                WHERE id = :server_id
                """
            ),
            {"server_id": str(server_id)},
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


def _row_to_alert_item(row: Any) -> AlertItem:
    data = dict(row)
    data["details"] = _normalize_json_field(data.get("details"))
    return AlertItem(**data)


def _row_to_uptime_monitor_item(row: Any) -> UptimeMonitorItem:
    return UptimeMonitorItem(**dict(row))


@app.post("/v1/uptime-monitors", response_model=UptimeMonitorItem)
def create_uptime_monitor(
    payload: UptimeMonitorCreateRequest,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> UptimeMonitorItem:
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO uptime_monitors (
                    name, url, check_interval_sec, timeout_sec, expected_status
                ) VALUES (
                    :name, :url, :check_interval_sec, :timeout_sec, :expected_status
                )
                RETURNING id, name, url, check_interval_sec, timeout_sec, expected_status,
                          last_status, last_response_time_ms, last_checked_at,
                          consecutive_failures, created_at
                """
            ),
            {
                "name": payload.name.strip(),
                "url": str(payload.url),
                "check_interval_sec": payload.check_interval_sec,
                "timeout_sec": payload.timeout_sec,
                "expected_status": payload.expected_status,
            },
        ).mappings().one()
    return _row_to_uptime_monitor_item(row)


@app.get("/v1/uptime-monitors", response_model=list[UptimeMonitorItem])
def list_uptime_monitors(_: AuthenticatedUser = Depends(require_authenticated_user)) -> list[UptimeMonitorItem]:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, name, url, check_interval_sec, timeout_sec, expected_status,
                       last_status, last_response_time_ms, last_checked_at,
                       consecutive_failures, created_at
                FROM uptime_monitors
                ORDER BY created_at DESC
                """
            )
        ).mappings().all()
    return [_row_to_uptime_monitor_item(row) for row in rows]


@app.get("/v1/uptime-monitors/{monitor_id}", response_model=UptimeMonitorItem)
def get_uptime_monitor(
    monitor_id: UUID,
    _: AuthenticatedUser = Depends(require_authenticated_user),
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
                """
            ),
            {"monitor_id": str(monitor_id)},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Uptime monitor not found", status_code=404)
    return _row_to_uptime_monitor_item(row)


@app.delete("/v1/uptime-monitors/{monitor_id}", response_model=UptimeMonitorDeleteResponse)
def delete_uptime_monitor(
    monitor_id: UUID,
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> UptimeMonitorDeleteResponse:
    with get_engine().begin() as conn:
        result = conn.execute(
            text("DELETE FROM uptime_monitors WHERE id = :monitor_id"),
            {"monitor_id": str(monitor_id)},
        )
        if not result.rowcount:
            raise APIError(code="not_found", message="Uptime monitor not found", status_code=404)
    return UptimeMonitorDeleteResponse(monitor_id=monitor_id)


@app.get("/v1/uptime-monitors/{monitor_id}/checks", response_model=list[UptimeCheckItem])
def list_uptime_checks(
    monitor_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[UptimeCheckItem]:
    with get_engine().connect() as conn:
        monitor_exists = conn.execute(
            text("SELECT 1 FROM uptime_monitors WHERE id = :monitor_id"),
            {"monitor_id": str(monitor_id)},
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
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> NotificationSettingItem:
    with get_engine().begin() as conn:
        row = svc_upsert_notification_setting(conn, payload.model_dump())
    return NotificationSettingItem(**row)


@app.get("/v1/notifications/settings", response_model=list[NotificationSettingItem])
def get_notifications_settings(
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[NotificationSettingItem]:
    with get_engine().connect() as conn:
        rows = svc_list_notification_settings(conn)
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

    with get_engine().begin() as conn:
        server = conn.execute(
            text(
                """
                SELECT id, name
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

        metadata_patch = {
            "host": payload.host.model_dump(exclude_none=True),
            "docker_container_count": len(payload.docker.containers or []),
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
        resolve_alert_type(conn, server["id"], "agent_offline")

        logs_inserted = 0
        restart_lines: list[str] = []
        max_logs = 300
        for unit, lines in (payload.logs.systemd or {}).items():
            for line in lines:
                if logs_inserted >= max_logs:
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
                logs_inserted += 1
                if is_service_restart_line(msg):
                    restart_lines.append(msg)
            if logs_inserted >= max_logs:
                break

        alerts_created = evaluate_metric_alerts(
            conn,
            server_id=server["id"],
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
    _: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[AlertItem]:
    conditions: list[str] = []
    params: dict[str, Any] = {}
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
