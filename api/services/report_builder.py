from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


def _fmt_dt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def build_daily_report(
    conn: Connection,
    *,
    user_id: UUID,
    email: str,
    now: datetime | None = None,
) -> tuple[str, str, str]:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    subject = f"AI DevOps Monitor Daily Report ({now.date().isoformat()})"

    servers = conn.execute(
        text(
            """
            SELECT id, name, status, last_seen_at
            FROM servers
            WHERE user_id = :user_id
            ORDER BY name ASC
            """
        ),
        {"user_id": str(user_id)},
    ).mappings().all()

    alert_counts = conn.execute(
        text(
            """
            SELECT severity, type, COUNT(*) AS count
            FROM alerts
            WHERE ts >= :since
              AND user_id = :user_id
            GROUP BY severity, type
            ORDER BY count DESC, severity DESC, type ASC
            """
        ),
        {"since": since, "user_id": str(user_id)},
    ).mappings().all()

    latest_alerts = conn.execute(
        text(
            """
            SELECT id, server_id, uptime_monitor_id, ts, type, severity, title, is_resolved, resolved_at
            FROM alerts
            WHERE ts >= :since
              AND user_id = :user_id
            ORDER BY ts DESC
            LIMIT 10
            """
        ),
        {"since": since, "user_id": str(user_id)},
    ).mappings().all()

    worst_metrics = conn.execute(
        text(
            """
            SELECT s.id AS server_id, s.name,
                   MAX(m.cpu_percent) AS max_cpu_percent,
                   MAX(m.ram_percent) AS max_ram_percent,
                   MAX(m.disk_percent) AS max_disk_percent
            FROM servers s
            LEFT JOIN metrics m ON m.server_id = s.id AND m.ts >= :since
            WHERE s.user_id = :user_id
            GROUP BY s.id, s.name
            ORDER BY s.name ASC
            """
        ),
        {"since": since, "user_id": str(user_id)},
    ).mappings().all()

    uptime_summary = conn.execute(
        text(
            """
            SELECT um.id, um.name, um.url, um.last_status, um.last_checked_at,
                   COALESCE(SUM(CASE WHEN uc.status = 'up' THEN 1 ELSE 0 END), 0) AS up_checks,
                   COALESCE(SUM(CASE WHEN uc.status = 'down' THEN 1 ELSE 0 END), 0) AS down_checks
            FROM uptime_monitors um
            LEFT JOIN uptime_checks uc
              ON uc.monitor_id = um.id AND uc.checked_at >= :since
            WHERE um.user_id = :user_id
            GROUP BY um.id, um.name, um.url, um.last_status, um.last_checked_at
            ORDER BY um.name ASC
            """
        ),
        {"since": since, "user_id": str(user_id)},
    ).mappings().all()

    text_lines: list[str] = []
    text_lines.append(f"AI DevOps Monitor Daily Report for {email}")
    text_lines.append(f"Window: {since.isoformat()} to {now.isoformat()}")
    text_lines.append("")
    text_lines.append("Servers")
    if not servers:
        text_lines.append("- No servers")
    for row in servers:
        text_lines.append(f"- {row['name']}: {row['status']} (last_seen={_fmt_dt(row['last_seen_at'])})")

    text_lines.append("")
    text_lines.append("Alert Counts (last 24h)")
    if not alert_counts:
        text_lines.append("- No alerts")
    for row in alert_counts:
        text_lines.append(f"- {row['severity']} / {row['type']}: {row['count']}")

    text_lines.append("")
    text_lines.append("Latest Alerts (top 10)")
    if not latest_alerts:
        text_lines.append("- No alerts in last 24h")
    for row in latest_alerts:
        target = row["server_id"] or row["uptime_monitor_id"] or "-"
        text_lines.append(
            f"- [{_fmt_dt(row['ts'])}] {row['severity']} {row['type']} target={target} resolved={row['is_resolved']} title={row['title']}"
        )

    text_lines.append("")
    text_lines.append("Worst Metrics (last 24h)")
    if not worst_metrics:
        text_lines.append("- No metrics")
    for row in worst_metrics:
        text_lines.append(
            f"- {row['name']}: max_cpu={row['max_cpu_percent'] or '-'} max_ram={row['max_ram_percent'] or '-'} max_disk={row['max_disk_percent'] or '-'}"
        )

    text_lines.append("")
    text_lines.append("Uptime Summary (last 24h)")
    if not uptime_summary:
        text_lines.append("- No uptime monitors")
    for row in uptime_summary:
        text_lines.append(
            f"- {row['name']}: last_status={row['last_status']} up_checks={row['up_checks']} down_checks={row['down_checks']} last_checked={_fmt_dt(row['last_checked_at'])}"
        )

    text_body = "\n".join(text_lines)

    def esc(v: Any) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    html = [
        "<html><body>",
        f"<h2>AI DevOps Monitor Daily Report</h2><p><strong>Recipient:</strong> {esc(email)}<br><strong>Window:</strong> {esc(since.isoformat())} to {esc(now.isoformat())}</p>",
        "<h3>Servers</h3><ul>",
    ]
    if not servers:
        html.append("<li>No servers</li>")
    for row in servers:
        html.append(f"<li>{esc(row['name'])}: {esc(row['status'])} (last_seen={esc(_fmt_dt(row['last_seen_at']))})</li>")
    html.append("</ul><h3>Alert Counts (last 24h)</h3><ul>")
    if not alert_counts:
        html.append("<li>No alerts</li>")
    for row in alert_counts:
        html.append(f"<li>{esc(row['severity'])} / {esc(row['type'])}: {esc(row['count'])}</li>")
    html.append("</ul><h3>Latest Alerts (top 10)</h3><ul>")
    if not latest_alerts:
        html.append("<li>No alerts in last 24h</li>")
    for row in latest_alerts:
        target = row["server_id"] or row["uptime_monitor_id"] or "-"
        html.append(
            f"<li>[{esc(_fmt_dt(row['ts']))}] {esc(row['severity'])} {esc(row['type'])} target={esc(target)} resolved={esc(row['is_resolved'])} title={esc(row['title'])}</li>"
        )
    html.append("</ul><h3>Worst Metrics (last 24h)</h3><ul>")
    if not worst_metrics:
        html.append("<li>No metrics</li>")
    for row in worst_metrics:
        html.append(
            f"<li>{esc(row['name'])}: max_cpu={esc(row['max_cpu_percent'] or '-')} max_ram={esc(row['max_ram_percent'] or '-')} max_disk={esc(row['max_disk_percent'] or '-')}</li>"
        )
    html.append("</ul><h3>Uptime Summary (last 24h)</h3><ul>")
    if not uptime_summary:
        html.append("<li>No uptime monitors</li>")
    for row in uptime_summary:
        html.append(
            f"<li>{esc(row['name'])}: last_status={esc(row['last_status'])} up_checks={esc(row['up_checks'])} down_checks={esc(row['down_checks'])} last_checked={esc(_fmt_dt(row['last_checked_at']))}</li>"
        )
    html.append("</ul></body></html>")

    return subject, text_body, "".join(html)
