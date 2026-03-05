from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import RowMapping

from ..alerts import create_alert_if_needed
from ..db import fetch_all, fetch_one, get_engine
from ..errors import APIError
from ..security import generate_app_key, hash_agent_token
from ..settings import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App Keys
# ---------------------------------------------------------------------------


def create_app_key_full(
    *, user_id: UUID, server_id: UUID, name: str
) -> dict[str, Any]:
    """Create a new app key for a server. Returns dict with raw_key included."""
    settings = get_settings()
    raw_key = generate_app_key()
    key_hash = hash_agent_token(raw_key, settings.agent_token_pepper)

    with get_engine().begin() as conn:
        server = conn.execute(
            text("SELECT id FROM servers WHERE id = :sid AND user_id = :uid"),
            {"sid": str(server_id), "uid": str(user_id)},
        ).first()
        if not server:
            raise APIError(code="not_found", message="Server not found", status_code=404)

        row = conn.execute(
            text(
                """
                INSERT INTO app_keys (server_id, user_id, name, key_hash)
                VALUES (:server_id, :user_id, :name, :key_hash)
                RETURNING id, server_id, name, created_at
                """
            ),
            {
                "server_id": str(server_id),
                "user_id": str(user_id),
                "name": name,
                "key_hash": key_hash,
            },
        ).mappings().one()

    return {**dict(row), "raw_key": raw_key}


def list_app_keys(*, user_id: UUID, server_id: UUID) -> list[RowMapping]:
    return fetch_all(
        """
        SELECT id, server_id, name, created_at, revoked_at
        FROM app_keys
        WHERE user_id = :user_id AND server_id = :server_id
        ORDER BY created_at DESC
        """,
        {"user_id": str(user_id), "server_id": str(server_id)},
    )


def revoke_app_key(*, user_id: UUID, key_id: UUID) -> dict[str, Any]:
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                UPDATE app_keys
                SET revoked_at = now()
                WHERE id = :key_id AND user_id = :user_id AND revoked_at IS NULL
                RETURNING id, revoked_at
                """
            ),
            {"key_id": str(key_id), "user_id": str(user_id)},
        ).mappings().first()
        if not row:
            raise APIError(code="not_found", message="App key not found or already revoked", status_code=404)
        return dict(row)


def validate_app_key(key_hash: str) -> dict[str, Any]:
    """Validate an app key hash. Returns key info including server_id and user_id."""
    row = fetch_one(
        """
        SELECT id, server_id, user_id, name
        FROM app_keys
        WHERE key_hash = :key_hash AND revoked_at IS NULL
        """,
        {"key_hash": key_hash},
    )
    if not row:
        raise APIError(code="unauthorized", message="Invalid or revoked app key", status_code=401)
    return dict(row)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def ingest_event(
    *,
    server_id: UUID,
    user_id: UUID,
    source: str,
    event: str,
    severity: str,
    meta: dict[str, Any],
    ip: str | None,
) -> dict[str, Any]:
    """Store an application event and check alert rules."""
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO app_events (server_id, user_id, source, event, severity, meta, ip)
                VALUES (:server_id, :user_id, :source, :event, :severity, CAST(:meta AS jsonb), :ip)
                RETURNING id
                """
            ),
            {
                "server_id": str(server_id),
                "user_id": str(user_id),
                "source": source,
                "event": event,
                "severity": severity,
                "meta": json.dumps(meta, separators=(",", ":"), default=str),
                "ip": ip,
            },
        ).mappings().one()

        # Check alert rules inline
        _evaluate_event_alert_rules(conn, server_id=server_id, user_id=user_id, event=event, source=source, severity=severity)

    return dict(row)


def list_events(
    *,
    user_id: UUID,
    server_id: UUID | None = None,
    source: str | None = None,
    event: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List app events with filtering."""
    where = ["e.user_id = :user_id"]
    params: dict[str, Any] = {"user_id": str(user_id), "limit": limit, "offset": offset}

    if server_id:
        where.append("e.server_id = :server_id")
        params["server_id"] = str(server_id)
    if source:
        where.append("e.source = :source")
        params["source"] = source
    if event:
        where.append("e.event = :event")
        params["event"] = event
    if severity:
        where.append("e.severity = :severity")
        params["severity"] = severity
    if q:
        where.append("(e.event ILIKE :q OR e.source ILIKE :q OR CAST(e.meta AS text) ILIKE :q)")
        params["q"] = f"%{q}%"
    if since:
        where.append("e.created_at >= :since")
        params["since"] = since
    if until:
        where.append("e.created_at <= :until")
        params["until"] = until

    where_clause = " AND ".join(where)

    items = fetch_all(
        f"""
        SELECT e.id, e.server_id, e.source, e.event, e.severity, e.meta, e.ip, e.created_at
        FROM app_events e
        WHERE {where_clause}
        ORDER BY e.created_at DESC
        LIMIT :limit OFFSET :offset
        """,
        params,
    )

    count_row = fetch_one(
        f"SELECT COUNT(*) AS total FROM app_events e WHERE {where_clause}",
        {k: v for k, v in params.items() if k not in ("limit", "offset")},
    )
    total = int(count_row["total"]) if count_row else 0

    return {"items": [dict(r) for r in items], "total": total}


# ---------------------------------------------------------------------------
# Event Alert Rules
# ---------------------------------------------------------------------------


def create_event_alert_rule(*, user_id: UUID, **kwargs: Any) -> dict[str, Any]:
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO event_alert_rules (user_id, server_id, name, event, source, severity_filter, threshold, window_seconds)
                VALUES (:user_id, :server_id, :name, :event, :source, :severity_filter, :threshold, :window_seconds)
                RETURNING id, server_id, name, event, source, severity_filter, threshold, window_seconds, is_enabled, created_at
                """
            ),
            {
                "user_id": str(user_id),
                "server_id": str(kwargs["server_id"]) if kwargs.get("server_id") else None,
                "name": kwargs["name"],
                "event": kwargs["event"],
                "source": kwargs.get("source"),
                "severity_filter": kwargs.get("severity_filter"),
                "threshold": kwargs.get("threshold", 10),
                "window_seconds": kwargs.get("window_seconds", 300),
            },
        ).mappings().one()
    return dict(row)


def list_event_alert_rules(*, user_id: UUID) -> list[RowMapping]:
    return fetch_all(
        """
        SELECT id, server_id, name, event, source, severity_filter, threshold, window_seconds, is_enabled, created_at
        FROM event_alert_rules
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        """,
        {"user_id": str(user_id)},
    )


def delete_event_alert_rule(*, user_id: UUID, rule_id: UUID) -> dict[str, Any]:
    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                DELETE FROM event_alert_rules
                WHERE id = :rule_id AND user_id = :user_id
                RETURNING id
                """
            ),
            {"rule_id": str(rule_id), "user_id": str(user_id)},
        ).mappings().first()
        if not row:
            raise APIError(code="not_found", message="Alert rule not found", status_code=404)
        return dict(row)


# ---------------------------------------------------------------------------
# Alert Evaluation (called inline on event ingest)
# ---------------------------------------------------------------------------


def _evaluate_event_alert_rules(
    conn,
    *,
    server_id: UUID,
    user_id: UUID,
    event: str,
    source: str,
    severity: str,
) -> None:
    """Check all matching alert rules and fire alerts if thresholds are exceeded."""
    settings = get_settings()

    rules = conn.execute(
        text(
            """
            SELECT id, server_id AS rule_server_id, name, event AS rule_event, source AS rule_source,
                   severity_filter, threshold, window_seconds
            FROM event_alert_rules
            WHERE user_id = :user_id
              AND is_enabled = TRUE
              AND event = :event
              AND (source IS NULL OR source = :source)
              AND (severity_filter IS NULL OR severity_filter = :severity)
              AND (server_id IS NULL OR server_id = :server_id)
            """
        ),
        {
            "user_id": str(user_id),
            "event": event,
            "source": source,
            "severity": severity,
            "server_id": str(server_id),
        },
    ).mappings().all()

    for rule in rules:
        count_row = conn.execute(
            text(
                """
                SELECT COUNT(*) AS cnt
                FROM app_events
                WHERE user_id = :user_id
                  AND event = :event
                  AND (CAST(:rule_server_id AS uuid) IS NULL OR server_id = :server_id)
                  AND (CAST(:rule_source AS text) IS NULL OR source = :rule_source)
                  AND (CAST(:severity_filter AS text) IS NULL OR severity = :severity_filter)
                  AND created_at >= now() - make_interval(secs => :window_seconds)
                """
            ),
            {
                "user_id": str(user_id),
                "event": event,
                "server_id": str(server_id),
                "rule_server_id": str(rule["rule_server_id"]) if rule["rule_server_id"] else None,
                "rule_source": rule["rule_source"],
                "severity_filter": rule["severity_filter"],
                "window_seconds": rule["window_seconds"],
            },
        ).mappings().one()

        if int(count_row["cnt"]) >= rule["threshold"]:
            alert_server_id = rule["rule_server_id"] or server_id
            create_alert_if_needed(
                conn,
                server_id=alert_server_id,
                alert_type="app_event_threshold",
                severity="high",
                title=f"App event threshold exceeded: {rule['name']}",
                details={
                    "rule_id": str(rule["id"]),
                    "rule_name": rule["name"],
                    "event": event,
                    "threshold": rule["threshold"],
                    "window_seconds": rule["window_seconds"],
                    "count": int(count_row["cnt"]),
                },
                dedupe_seconds=rule["window_seconds"],
            )
