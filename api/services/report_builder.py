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
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def _esc(v: Any) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _humanize_alert_type(value: Any) -> str:
    return str(value).replace("_", " ").replace("-", " ").title()


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

    def _table(headers: list[str], rows_html: list[str], empty_html: str) -> str:
        if not rows_html:
            return empty_html
        head = "".join(
            f"<th style=\"text-align:left;padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em\">{_esc(h)}</th>"
            for h in headers
        )
        body = "".join(rows_html)
        return (
            "<table style=\"width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden\">"
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        )

    server_rows = [
        (
            "<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['name'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['status'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(_fmt_dt(r['last_seen_at']))}</td>"
            "</tr>"
        )
        for r in servers
    ]
    alert_count_rows = [
        (
            "<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['severity'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(_humanize_alert_type(r['type']))}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['count'])}</td>"
            "</tr>"
        )
        for r in alert_counts
    ]
    latest_alert_rows = []
    for r in latest_alerts:
        target = r["server_id"] or r["uptime_monitor_id"] or "-"
        latest_alert_rows.append(
            "<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(_fmt_dt(r['ts']))}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['severity'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(_humanize_alert_type(r['type']))}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(target)}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['title'])}</td>"
            "</tr>"
        )
    metric_rows = [
        (
            "<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['name'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['max_cpu_percent'] or '-')}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['max_ram_percent'] or '-')}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['max_disk_percent'] or '-')}</td>"
            "</tr>"
        )
        for r in worst_metrics
    ]
    uptime_rows = [
        (
            "<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['name'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['last_status'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['up_checks'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(r['down_checks'])}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #f3f4f6\">{_esc(_fmt_dt(r['last_checked_at']))}</td>"
            "</tr>"
        )
        for r in uptime_summary
    ]

    html = [
        "<html><body style=\"margin:0;padding:24px;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827\">",
        "<div style=\"max-width:980px;margin:0 auto\">",
        "<div style=\"background:#111827;color:#ffffff;border-radius:16px;padding:20px 24px;margin-bottom:16px\">",
        "<div style=\"font-size:12px;opacity:.85;letter-spacing:.06em;text-transform:uppercase\">AI DevOps Monitor</div>",
        "<div style=\"font-size:28px;font-weight:700;margin-top:6px\">Daily Report</div>",
        f"<div style=\"font-size:13px;opacity:.9;margin-top:6px\">Recipient: {_esc(email)} | Window: {_esc(_fmt_dt(since))} to {_esc(_fmt_dt(now))}</div>",
        "</div>",
        "<div style=\"display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px\">",
        f"<div style=\"background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px\"><div style=\"font-size:12px;color:#6b7280\">Servers</div><div style=\"font-size:24px;font-weight:700\">{len(servers)}</div></div>",
        f"<div style=\"background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px\"><div style=\"font-size:12px;color:#6b7280\">Alerts (24h)</div><div style=\"font-size:24px;font-weight:700\">{sum(int(r['count']) for r in alert_counts) if alert_counts else 0}</div></div>",
        f"<div style=\"background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px\"><div style=\"font-size:12px;color:#6b7280\">Uptime Monitors</div><div style=\"font-size:24px;font-weight:700\">{len(uptime_summary)}</div></div>",
        f"<div style=\"background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px\"><div style=\"font-size:12px;color:#6b7280\">Generated</div><div style=\"font-size:18px;font-weight:700\">{_esc(_fmt_dt(now))}</div></div>",
        "</div>",
    ]

    sections = [
        ("Servers", _table(["Name", "Status", "Last Seen"], server_rows, "<div style=\"padding:12px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:12px\">No servers</div>")),
        ("Alert Counts (Last 24h)", _table(["Severity", "Type", "Count"], alert_count_rows, "<div style=\"padding:12px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:12px\">No alerts</div>")),
        ("Latest Alerts (Top 10)", _table(["Time", "Severity", "Type", "Target", "Title"], latest_alert_rows, "<div style=\"padding:12px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:12px\">No alerts in last 24h</div>")),
        ("Worst Metrics (Last 24h)", _table(["Server", "Max CPU %", "Max RAM %", "Max Disk %"], metric_rows, "<div style=\"padding:12px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:12px\">No metrics</div>")),
        ("Uptime Summary (Last 24h)", _table(["Monitor", "Last Status", "Up Checks", "Down Checks", "Last Checked"], uptime_rows, "<div style=\"padding:12px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:12px\">No uptime monitors</div>")),
    ]

    for title, section_html in sections:
        html.append(f"<div style=\"margin:18px 0 8px 0;font-size:18px;font-weight:700\">{_esc(title)}</div>")
        html.append(section_html)

    html.append("</div></body></html>")

    return subject, text_body, "".join(html)
