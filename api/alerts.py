from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from .services.notification_service import notify_for_alert_change


def infer_log_level(message: str) -> str:
    lowered = message.lower()
    if "error" in lowered:
        return "error"
    if "warn" in lowered:
        return "warn"
    return "info"


def _metric_alert_thresholds(conn: Connection, *, owner_user_id: UUID | None) -> dict[str, int]:
    defaults = {"cpu": 90, "ram": 90, "disk": 90}
    if owner_user_id is None:
        return defaults
    try:
        row = conn.execute(
            text(
                """
                SELECT
                    MIN(cpu_threshold) AS min_cpu_threshold,
                    MIN(ram_threshold) AS min_ram_threshold,
                    MIN(disk_threshold) AS min_disk_threshold
                FROM notification_settings
                WHERE is_enabled = TRUE
                  AND user_id = :user_id
                """
            ),
            {"user_id": str(owner_user_id)},
        ).mappings().first()
    except Exception:
        return defaults
    if not row:
        return defaults
    return {
        "cpu": int(row["min_cpu_threshold"] or defaults["cpu"]),
        "ram": int(row["min_ram_threshold"] or defaults["ram"]),
        "disk": int(row["min_disk_threshold"] or defaults["disk"]),
    }


def is_service_restart_line(message: str) -> bool:
    lowered = message.lower()
    return "started" in lowered or "restart" in lowered or "reloaded" in lowered


def _target_where_clause(server_id: UUID | None, uptime_monitor_id: UUID | None) -> str:
    if (server_id is None) == (uptime_monitor_id is None):
        raise ValueError("Exactly one of server_id or uptime_monitor_id must be provided")
    if server_id is not None:
        return "server_id = :server_id AND uptime_monitor_id IS NULL"
    return "uptime_monitor_id = :uptime_monitor_id AND server_id IS NULL"


def _target_params(server_id: UUID | None, uptime_monitor_id: UUID | None) -> dict[str, str]:
    params: dict[str, str] = {}
    if server_id is not None:
        params["server_id"] = str(server_id)
    if uptime_monitor_id is not None:
        params["uptime_monitor_id"] = str(uptime_monitor_id)
    return params


def resolve_alert_type(
    conn: Connection,
    server_id: UUID | None,
    alert_type: str,
    *,
    uptime_monitor_id: UUID | None = None,
) -> int:
    target_clause = _target_where_clause(server_id, uptime_monitor_id)
    params = _target_params(server_id, uptime_monitor_id)
    params["alert_type"] = alert_type
    result = conn.execute(
        text(
            """
            UPDATE alerts
            SET is_resolved = TRUE, resolved_at = now()
            WHERE {target_clause}
              AND type = :alert_type
              AND is_resolved = FALSE
            RETURNING id, user_id, server_id, uptime_monitor_id, ts, type, severity, title, details, is_resolved, resolved_at
            """
            .replace("{target_clause}", target_clause)
        ),
        params,
    )
    rows = result.mappings().all()
    for row in rows:
        try:
            notify_for_alert_change(conn, dict(row), is_recovery=True)
        except Exception:
            # Notification failures must never block alert resolution.
            pass
    return len(rows)


def create_alert_if_needed(
    conn: Connection,
    *,
    server_id: UUID | None = None,
    uptime_monitor_id: UUID | None = None,
    alert_type: str,
    severity: str,
    title: str,
    details: dict[str, Any],
    dedupe_seconds: int,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now(timezone.utc)
    target_clause = _target_where_clause(server_id, uptime_monitor_id)
    target_params = _target_params(server_id, uptime_monitor_id)

    unresolved = conn.execute(
        text(
            """
            SELECT id
            FROM alerts
            WHERE {target_clause}
              AND type = :alert_type
              AND is_resolved = FALSE
            LIMIT 1
            """
            .replace("{target_clause}", target_clause)
        ),
        {**target_params, "alert_type": alert_type},
    ).first()
    if unresolved:
        return False

    latest = conn.execute(
        text(
            """
            SELECT ts
            FROM alerts
            WHERE {target_clause}
              AND type = :alert_type
            ORDER BY ts DESC
            LIMIT 1
            """
            .replace("{target_clause}", target_clause)
        ),
        {**target_params, "alert_type": alert_type},
    ).scalar()

    if latest is not None:
        age_seconds = (now - latest).total_seconds()
        if age_seconds < dedupe_seconds:
            return False

    row = conn.execute(
        text(
            """
            INSERT INTO alerts (user_id, server_id, uptime_monitor_id, type, severity, title, details)
            VALUES (
                CASE
                    WHEN :server_id IS NOT NULL THEN (
                        SELECT s.user_id FROM servers s WHERE s.id = CAST(:server_id AS uuid)
                    )
                    WHEN :uptime_monitor_id IS NOT NULL THEN (
                        SELECT um.user_id FROM uptime_monitors um WHERE um.id = CAST(:uptime_monitor_id AS uuid)
                    )
                    ELSE NULL
                END,
                :server_id,
                :uptime_monitor_id,
                :alert_type,
                :severity,
                :title,
                CAST(:details AS jsonb)
            )
            RETURNING id, user_id, server_id, uptime_monitor_id, ts, type, severity, title, details, is_resolved, resolved_at
            """
        ),
        {
            "server_id": str(server_id) if server_id is not None else None,
            "uptime_monitor_id": str(uptime_monitor_id) if uptime_monitor_id is not None else None,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "details": _json_dump(details),
        },
    ).mappings().one()
    try:
        notify_for_alert_change(conn, dict(row), is_recovery=False)
    except Exception:
        # Notification failures must never block alert creation.
        pass
    return True


def evaluate_metric_alerts(
    conn: Connection,
    *,
    server_id: UUID,
    owner_user_id: UUID | None,
    cpu_percent: float | None,
    ram_percent: float | None,
    disk_percent: float | None,
    dedupe_seconds: int,
) -> list[str]:
    created: list[str] = []
    thresholds = _metric_alert_thresholds(conn, owner_user_id=owner_user_id)
    if cpu_percent is not None and cpu_percent >= thresholds["cpu"]:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="cpu_high",
            severity="high",
            title="CPU usage is high",
            details={"cpu_percent": cpu_percent, "threshold": thresholds["cpu"]},
            dedupe_seconds=dedupe_seconds,
        ):
            created.append("cpu_high")
    if ram_percent is not None and ram_percent >= thresholds["ram"]:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="ram_high",
            severity="high",
            title="RAM usage is high",
            details={"ram_percent": ram_percent, "threshold": thresholds["ram"]},
            dedupe_seconds=dedupe_seconds,
        ):
            created.append("ram_high")
    if disk_percent is not None and disk_percent >= thresholds["disk"]:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="disk_high",
            severity="critical",
            title="Disk usage is high",
            details={"disk_percent": disk_percent, "threshold": thresholds["disk"]},
            dedupe_seconds=dedupe_seconds,
        ):
            created.append("disk_high")
    return created


def maybe_create_service_restart_alert(
    conn: Connection,
    *,
    server_id: UUID,
    matched_lines: list[str],
    dedupe_seconds: int,
) -> bool:
    sample = matched_lines[:5]
    return create_alert_if_needed(
        conn,
        server_id=server_id,
        alert_type="service_restart",
        severity="medium",
        title="Service restart/reload detected",
        details={"matches": sample, "count": len(matched_lines)},
        dedupe_seconds=dedupe_seconds,
    )


def _json_dump(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, separators=(",", ":"), default=str)
