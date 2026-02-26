from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from ..errors import APIError
from ..settings import get_settings
from .mailer import MailPayload, send_email
from .report_builder import build_daily_report

logger = logging.getLogger(__name__)

IMMEDIATE_ALERT_SEVERITIES = {"high", "critical"}


def _normalize_alert_details(details: Any) -> dict[str, Any]:
    if isinstance(details, dict):
        return details
    if isinstance(details, str):
        import json

        try:
            parsed = json.loads(details)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _parse_time(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def _esc(value: Any) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _humanize_alert_type(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def _severity_color(severity: Any) -> str:
    s = str(severity or "").lower()
    if s == "critical":
        return "#b91c1c"
    if s == "high":
        return "#c2410c"
    if s == "medium":
        return "#92400e"
    return "#374151"


def _target_name(conn: Connection, alert: dict[str, Any]) -> tuple[str, str]:
    server_id = alert.get("server_id")
    if server_id:
        row = conn.execute(
            text("SELECT name FROM servers WHERE id = :id"),
            {"id": str(server_id)},
        ).mappings().first()
        return ("Server", str(row["name"]) if row else str(server_id))

    monitor_id = alert.get("uptime_monitor_id")
    if monitor_id:
        row = conn.execute(
            text("SELECT name FROM uptime_monitors WHERE id = :id"),
            {"id": str(monitor_id)},
        ).mappings().first()
        return ("Uptime Monitor", str(row["name"]) if row else str(monitor_id))

    return ("Target", "-")


def _metric_summary_html(alert_type: str, details: dict[str, Any]) -> str:
    value_key_map = {
        "disk_high": ("disk_percent", "Disk Usage"),
        "cpu_high": ("cpu_percent", "CPU Usage"),
        "ram_high": ("ram_percent", "RAM Usage"),
        "UPTIME_SLOW": ("response_time_ms", "Response Time (ms)"),
    }
    item = value_key_map.get(alert_type)
    if not item:
        return ""
    key, label = item
    value = details.get(key)
    if value is None:
        return ""

    threshold = details.get("threshold") or details.get("threshold_ms")
    suffix = "%" if "percent" in key else " ms"
    try:
        numeric = float(value)
        display_value = f"{numeric:.1f}{suffix}" if suffix == "%" else f"{int(numeric)}{suffix}"
    except Exception:
        display_value = f"{value}{suffix}"

    threshold_text = ""
    if threshold is not None:
        threshold_text = f"<div style=\"font-size:12px;color:#6b7280;margin-top:4px\">Threshold: {_esc(threshold)}{suffix if suffix == '%' else ' ms'}</div>"

    return (
        "<div style=\"margin:14px 0 18px 0;padding:14px 16px;border:1px solid #e5e7eb;border-radius:12px;background:#f9fafb\">"
        f"<div style=\"font-size:12px;color:#6b7280;letter-spacing:.04em;text-transform:uppercase\">{_esc(label)}</div>"
        f"<div style=\"font-size:28px;font-weight:700;color:#111827;line-height:1.2\">{_esc(display_value)}</div>"
        f"{threshold_text}"
        "</div>"
    )


def _is_valid_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]


def _insert_notification_event(
    conn: Connection,
    *,
    key: str,
    email: str,
    alert_id: int | None,
    event_type: str,
    status: str,
    error: str | None,
) -> bool:
    try:
        conn.execute(
            text(
                """
                INSERT INTO notification_events (key, email, alert_id, event_type, status, error)
                VALUES (:key, :email, :alert_id, :event_type, :status, :error)
                """
            ),
            {
                "key": key,
                "email": email,
                "alert_id": alert_id,
                "event_type": event_type,
                "status": status,
                "error": error,
            },
        )
        return True
    except IntegrityError:
        return False


def _alert_event_key(alert_id: int, email: str, phase: str) -> str:
    return f"ALERT:{alert_id}:{phase}:EMAIL:{email.lower()}"


def _should_send_for_recipient(alert: dict[str, Any], recipient: dict[str, Any], *, is_recovery: bool) -> bool:
    if not bool(recipient.get("is_enabled", True)):
        return False
    if is_recovery:
        return True

    severity = str(alert.get("severity") or "").lower()
    if severity not in IMMEDIATE_ALERT_SEVERITIES:
        return False

    alert_type = str(alert.get("type") or "")
    details = _normalize_alert_details(alert.get("details"))

    if alert_type == "cpu_high":
        metric = details.get("cpu_percent")
        return metric is None or float(metric) >= int(recipient.get("cpu_threshold") or 80)
    if alert_type == "disk_high":
        metric = details.get("disk_percent")
        return metric is None or float(metric) >= int(recipient.get("disk_threshold") or 85)
    if alert_type == "ram_high":
        metric = details.get("ram_percent")
        return metric is None or float(metric) >= int(recipient.get("ram_threshold") or 85)
    if alert_type == "agent_offline":
        observed = details.get("offline_after_seconds")
        return observed is None or int(observed) >= int(recipient.get("offline_threshold_sec") or 120)

    return True


def _fetch_enabled_recipients(conn: Connection, *, user_id: UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            text(
                """
                SELECT id, user_id, email, is_enabled, cpu_threshold, disk_threshold, ram_threshold,
                       offline_threshold_sec, daily_report_time_utc, created_at
                FROM notification_settings
                WHERE is_enabled = TRUE
                  AND user_id = :user_id
                ORDER BY created_at ASC
                """
            ),
            {"user_id": str(user_id)},
        ).mappings().all()
    ]


def _alert_owner_user_id(conn: Connection, alert: dict[str, Any]) -> UUID | None:
    raw_user_id = alert.get("user_id")
    if raw_user_id:
        try:
            return UUID(str(raw_user_id))
        except Exception:
            pass

    server_id = alert.get("server_id")
    if server_id:
        value = conn.execute(
            text("SELECT user_id FROM servers WHERE id = :server_id"),
            {"server_id": str(server_id)},
        ).scalar()
        if value:
            return UUID(str(value))

    uptime_monitor_id = alert.get("uptime_monitor_id")
    if uptime_monitor_id:
        value = conn.execute(
            text("SELECT user_id FROM uptime_monitors WHERE id = :monitor_id"),
            {"monitor_id": str(uptime_monitor_id)},
        ).scalar()
        if value:
            return UUID(str(value))
    return None


def _send_alert_notification(conn: Connection, *, recipient: dict[str, Any], alert: dict[str, Any], is_recovery: bool) -> None:
    alert_id = int(alert["id"])
    email = str(recipient["email"]).strip().lower()
    phase = "RESOLVED" if is_recovery else "CREATED"
    dedupe_key = _alert_event_key(alert_id, email, phase)

    exists = conn.execute(
        text("SELECT 1 FROM notification_events WHERE key = :key LIMIT 1"),
        {"key": dedupe_key},
    ).first()
    if exists:
        return

    settings = get_settings()
    alert_type = str(alert.get("type") or "")
    target_label, target_value = _target_name(conn, alert)
    subject_prefix = "[Recovered]" if is_recovery else "[Alert]"
    subject = f"{subject_prefix} {_humanize_alert_type(alert_type)} - {target_value}"
    details = _normalize_alert_details(alert.get("details"))
    details_pretty = json.dumps(details, indent=2, ensure_ascii=False, default=str)
    severity_color = _severity_color(alert.get("severity"))
    metric_box = _metric_summary_html(alert_type, details)

    text_body = "\n".join(
        [
            "AI DevOps Monitor Notification",
            f"Recipient: {email}",
            f"Alert ID: {alert_id}",
            f"Type: {alert_type}",
            f"Severity: {alert.get('severity')}",
            f"Title: {alert.get('title')}",
            f"{target_label}: {target_value}",
            f"Created At: {_parse_time(alert.get('ts'))}",
            f"Resolved: {bool(alert.get('is_resolved'))}",
            f"Resolved At: {_parse_time(alert.get('resolved_at'))}",
            f"Server ID: {alert.get('server_id') or '-'}",
            f"Uptime Monitor ID: {alert.get('uptime_monitor_id') or '-'}",
            f"Details: {details}",
            f"API Base URL: {settings.api_base_url}",
        ]
    )

    html_body = (
        "<html><body style=\"margin:0;padding:24px;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827\">"
        "<div style=\"max-width:720px;margin:0 auto\">"
        "<div style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden\">"
        f"<div style=\"padding:18px 20px;background:{severity_color};color:#ffffff\">"
        f"<div style=\"font-size:12px;opacity:.9;letter-spacing:.06em;text-transform:uppercase\">AI DevOps Monitor</div>"
        f"<div style=\"font-size:22px;font-weight:700;margin-top:4px\">{_esc(_humanize_alert_type(alert_type))}</div>"
        f"<div style=\"font-size:13px;opacity:.95;margin-top:4px\">{_esc(target_label)}: {_esc(target_value)}</div>"
        "</div>"
        "<div style=\"padding:20px\">"
        f"<div style=\"font-size:18px;font-weight:700;color:#111827;margin-bottom:8px\">{_esc(alert.get('title') or '')}</div>"
        f"<div style=\"font-size:13px;color:#6b7280;margin-bottom:10px\">Severity: <strong style=\"color:{severity_color}\">{_esc(alert.get('severity') or '')}</strong></div>"
        f"{metric_box}"
        "<table style=\"width:100%;border-collapse:collapse;font-size:14px\">"
        f"<tr><td style=\"padding:8px 0;color:#6b7280;width:180px\">Created At</td><td style=\"padding:8px 0\">{_esc(_parse_time(alert.get('ts')))}</td></tr>"
        f"<tr><td style=\"padding:8px 0;color:#6b7280\">Resolved</td><td style=\"padding:8px 0\">{_esc(bool(alert.get('is_resolved')))}</td></tr>"
        f"<tr><td style=\"padding:8px 0;color:#6b7280\">Resolved At</td><td style=\"padding:8px 0\">{_esc(_parse_time(alert.get('resolved_at')))}</td></tr>"
        f"<tr><td style=\"padding:8px 0;color:#6b7280\">Server ID</td><td style=\"padding:8px 0;font-family:ui-monospace,Menlo,monospace\">{_esc(alert.get('server_id') or '-')}</td></tr>"
        f"<tr><td style=\"padding:8px 0;color:#6b7280\">Uptime Monitor ID</td><td style=\"padding:8px 0;font-family:ui-monospace,Menlo,monospace\">{_esc(alert.get('uptime_monitor_id') or '-')}</td></tr>"
        "</table>"
        "<div style=\"margin-top:16px\">"
        "<div style=\"font-size:12px;color:#6b7280;letter-spacing:.04em;text-transform:uppercase;margin-bottom:6px\">Alert Details</div>"
        f"<pre style=\"margin:0;padding:12px;border-radius:10px;background:#f9fafb;border:1px solid #e5e7eb;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.5\">{_esc(details_pretty)}</pre>"
        "</div>"
        f"<div style=\"margin-top:16px;font-size:12px;color:#6b7280\">API: {_esc(settings.api_base_url)}</div>"
        "</div></div></div></body></html>"
    )

    try:
        send_email(MailPayload(to_email=email, subject=subject, text_body=text_body, html_body=html_body))
        _insert_notification_event(
            conn,
            key=dedupe_key,
            email=email,
            alert_id=alert_id,
            event_type="ALERT_EMAIL",
            status="sent",
            error=None,
        )
    except Exception as exc:
        logger.exception(
            "alert_email_send_failed",
            extra={"event": "alert_email_send_failed", "email": email, "alert_id": alert_id},
        )
        _insert_notification_event(
            conn,
            key=dedupe_key,
            email=email,
            alert_id=alert_id,
            event_type="ALERT_EMAIL",
            status="failed",
            error=str(exc)[:1000],
        )


def notify_for_alert_change(conn: Connection, alert: dict[str, Any], *, is_recovery: bool) -> None:
    settings = get_settings()
    if is_recovery and not settings.send_recovery_emails:
        return

    owner_user_id = _alert_owner_user_id(conn, alert)
    if owner_user_id is None:
        return

    try:
        recipients = _fetch_enabled_recipients(conn, user_id=owner_user_id)
    except Exception:
        logger.exception("notification_fetch_recipients_failed", extra={"event": "notification_fetch_recipients_failed"})
        return

    for recipient in recipients:
        email = str(recipient.get("email") or "").strip()
        if not email or not _is_valid_email(email):
            continue
        if not _should_send_for_recipient(alert, recipient, is_recovery=is_recovery):
            continue
        _send_alert_notification(conn, recipient=recipient, alert=alert, is_recovery=is_recovery)


def upsert_notification_setting(conn: Connection, user_id: UUID, payload: dict[str, Any]) -> dict[str, Any]:
    email = str(payload.get("email", "")).strip().lower()
    if not _is_valid_email(email):
        raise APIError(code="bad_request", message="Invalid email", status_code=400)

    row = conn.execute(
        text(
            """
            INSERT INTO notification_settings (
                user_id, email, is_enabled, cpu_threshold, disk_threshold, ram_threshold,
                offline_threshold_sec, daily_report_time_utc
            ) VALUES (
                :user_id, :email, :is_enabled, :cpu_threshold, :disk_threshold, :ram_threshold,
                :offline_threshold_sec, :daily_report_time_utc
            )
            ON CONFLICT (user_id, email) DO UPDATE
            SET is_enabled = EXCLUDED.is_enabled,
                cpu_threshold = EXCLUDED.cpu_threshold,
                disk_threshold = EXCLUDED.disk_threshold,
                ram_threshold = EXCLUDED.ram_threshold,
                offline_threshold_sec = EXCLUDED.offline_threshold_sec,
                daily_report_time_utc = EXCLUDED.daily_report_time_utc
            RETURNING id, email, is_enabled, cpu_threshold, disk_threshold, ram_threshold,
                      offline_threshold_sec, daily_report_time_utc, created_at
            """
        ),
        {
            "email": email,
            "user_id": str(user_id),
            "is_enabled": bool(payload.get("is_enabled", True)),
            "cpu_threshold": int(payload.get("cpu_threshold", 80)),
            "disk_threshold": int(payload.get("disk_threshold", 85)),
            "ram_threshold": int(payload.get("ram_threshold", 85)),
            "offline_threshold_sec": int(payload.get("offline_threshold_sec", 120)),
            "daily_report_time_utc": str(payload.get("daily_report_time_utc", "08:00")),
        },
    ).mappings().one()
    return dict(row)


def list_notification_settings(conn: Connection, user_id: UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            """
            SELECT id, email, is_enabled, cpu_threshold, disk_threshold, ram_threshold,
                   offline_threshold_sec, daily_report_time_utc, created_at
            FROM notification_settings
            WHERE user_id = :user_id
            ORDER BY created_at ASC
            """
        ),
        {"user_id": str(user_id)},
    ).mappings().all()
    return [dict(row) for row in rows]


def send_test_email(to_email: str, api_base_url: str) -> None:
    to_email = to_email.strip().lower()
    if not _is_valid_email(to_email):
        raise APIError(code="bad_request", message="Invalid email", status_code=400)
    send_email(
        MailPayload(
            to_email=to_email,
            subject="[Test] AI DevOps Monitor Email",
            text_body=(
                "This is a test email from AI DevOps Monitor.\n"
                f"UTC: {datetime.now(timezone.utc).isoformat()}\n"
                f"API: {api_base_url}\n"
            ),
            html_body=(
                "<html><body><h3>AI DevOps Monitor Test Email</h3>"
                f"<p>UTC: {datetime.now(timezone.utc).isoformat()}<br>API: {api_base_url}</p></body></html>"
            ),
        )
    )


def _due_recipients_for_daily_report(conn: Connection, now: datetime) -> list[dict[str, Any]]:
    hhmm = now.strftime("%H:%M")
    rows = conn.execute(
        text(
            """
            SELECT id, user_id, email, is_enabled, daily_report_time_utc
            FROM notification_settings
            WHERE is_enabled = TRUE
              AND user_id IS NOT NULL
              AND to_char(daily_report_time_utc, 'HH24:MI') = :hhmm
            ORDER BY created_at ASC
            """
        ),
        {"hhmm": hhmm},
    ).mappings().all()
    return [dict(r) for r in rows]


def _daily_event_key(day: str, user_id: UUID, email: str) -> str:
    return f"DAILY:{day}:USER:{user_id}:EMAIL:{email.lower()}"


def _send_daily_report_for_recipient(conn: Connection, recipient: dict[str, Any], now: datetime) -> None:
    email = str(recipient["email"]).strip().lower()
    user_id = UUID(str(recipient["user_id"]))
    key = _daily_event_key(now.date().isoformat(), user_id, email)
    already = conn.execute(text("SELECT 1 FROM notification_events WHERE key = :key LIMIT 1"), {"key": key}).first()
    if already:
        return

    try:
        subject, text_body, html_body = build_daily_report(conn, user_id=user_id, email=email, now=now)
        send_email(MailPayload(to_email=email, subject=subject, text_body=text_body, html_body=html_body))
        _insert_notification_event(
            conn,
            key=key,
            email=email,
            alert_id=None,
            event_type="DAILY_REPORT",
            status="sent",
            error=None,
        )
    except Exception as exc:
        logger.exception("daily_report_send_failed", extra={"event": "daily_report_send_failed", "email": email})
        _insert_notification_event(
            conn,
            key=key,
            email=email,
            alert_id=None,
            event_type="DAILY_REPORT",
            status="failed",
            error=str(exc)[:1000],
        )


def run_daily_reports_sync() -> None:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    recipients: list[dict[str, Any]] = []
    try:
        with get_engine().begin() as conn:  # imported lazily to avoid cycles during module import
            recipients = _due_recipients_for_daily_report(conn, now)
            for recipient in recipients:
                _send_daily_report_for_recipient(conn, recipient, now)
    except Exception:
        logger.exception("daily_reports_cycle_failed", extra={"event": "daily_reports_cycle_failed", "at_utc": now.isoformat()})
        return
    if recipients:
        logger.info(
            "daily_reports_cycle_completed",
            extra={"event": "daily_reports_cycle_completed", "recipients": len(recipients), "at_utc": now.isoformat()},
        )


async def run_daily_reports_cycle() -> None:
    await asyncio.to_thread(run_daily_reports_sync)


# Lazy import to avoid import cycle at module top.
from ..db import get_engine  # noqa: E402
