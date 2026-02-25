from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


def infer_log_level(message: str) -> str:
    lowered = message.lower()
    if "error" in lowered:
        return "error"
    if "warn" in lowered:
        return "warn"
    return "info"


def is_service_restart_line(message: str) -> bool:
    lowered = message.lower()
    return "started" in lowered or "restart" in lowered or "reloaded" in lowered


def resolve_alert_type(conn: Connection, server_id: UUID, alert_type: str) -> int:
    result = conn.execute(
        text(
            """
            UPDATE alerts
            SET is_resolved = TRUE, resolved_at = now()
            WHERE server_id = :server_id
              AND type = :alert_type
              AND is_resolved = FALSE
            """
        ),
        {"server_id": str(server_id), "alert_type": alert_type},
    )
    return int(result.rowcount or 0)


def create_alert_if_needed(
    conn: Connection,
    *,
    server_id: UUID,
    alert_type: str,
    severity: str,
    title: str,
    details: dict[str, Any],
    dedupe_seconds: int,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now(timezone.utc)

    unresolved = conn.execute(
        text(
            """
            SELECT id
            FROM alerts
            WHERE server_id = :server_id
              AND type = :alert_type
              AND is_resolved = FALSE
            LIMIT 1
            """
        ),
        {"server_id": str(server_id), "alert_type": alert_type},
    ).first()
    if unresolved:
        return False

    latest = conn.execute(
        text(
            """
            SELECT ts
            FROM alerts
            WHERE server_id = :server_id
              AND type = :alert_type
            ORDER BY ts DESC
            LIMIT 1
            """
        ),
        {"server_id": str(server_id), "alert_type": alert_type},
    ).scalar()

    if latest is not None:
        age_seconds = (now - latest).total_seconds()
        if age_seconds < dedupe_seconds:
            return False

    conn.execute(
        text(
            """
            INSERT INTO alerts (server_id, type, severity, title, details)
            VALUES (:server_id, :alert_type, :severity, :title, CAST(:details AS jsonb))
            """
        ),
        {
            "server_id": str(server_id),
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "details": _json_dump(details),
        },
    )
    return True


def evaluate_metric_alerts(
    conn: Connection,
    *,
    server_id: UUID,
    cpu_percent: float | None,
    ram_percent: float | None,
    disk_percent: float | None,
    dedupe_seconds: int,
) -> list[str]:
    created: list[str] = []
    if cpu_percent is not None and cpu_percent >= 90:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="cpu_high",
            severity="high",
            title="CPU usage is high",
            details={"cpu_percent": cpu_percent, "threshold": 90},
            dedupe_seconds=dedupe_seconds,
        ):
            created.append("cpu_high")
    if ram_percent is not None and ram_percent >= 90:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="ram_high",
            severity="high",
            title="RAM usage is high",
            details={"ram_percent": ram_percent, "threshold": 90},
            dedupe_seconds=dedupe_seconds,
        ):
            created.append("ram_high")
    if disk_percent is not None and disk_percent >= 90:
        if create_alert_if_needed(
            conn,
            server_id=server_id,
            alert_type="disk_high",
            severity="critical",
            title="Disk usage is high",
            details={"disk_percent": disk_percent, "threshold": 90},
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
