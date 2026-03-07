from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text

from ..db import get_engine
from ..errors import APIError
from ..settings import get_settings
from .platform_service import build_chat_context_packet
from .llm_provider import generate_assistant_reply


def _normalize_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def create_chat_session(*, user_id: UUID, server_id: UUID, title: str | None) -> dict[str, Any]:
    with get_engine().begin() as conn:
        server = conn.execute(
            text("SELECT id, name FROM servers WHERE id = :server_id AND user_id = :user_id"),
            {"server_id": str(server_id), "user_id": str(user_id)},
        ).mappings().first()
        if not server:
            raise APIError(code="not_found", message="Server not found", status_code=404)

        final_title = (title or "").strip() or f"{server['name']} troubleshooting"
        row = conn.execute(
            text(
                """
                INSERT INTO chat_sessions (user_id, server_id, title, mode, last_message_at, updated_at)
                VALUES (:user_id, :server_id, :title, 'suggest_only', now(), now())
                RETURNING id, server_id, title, mode, created_at, updated_at, last_message_at
                """
            ),
            {"user_id": str(user_id), "server_id": str(server_id), "title": final_title},
        ).mappings().one()
    return dict(row)


def list_chat_sessions(*, user_id: UUID, server_id: UUID | None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"user_id": str(user_id)}
    filters = ["user_id = :user_id"]
    if server_id is not None:
        filters.append("server_id = :server_id")
        params["server_id"] = str(server_id)
    where_clause = " AND ".join(filters)

    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                f"""
                SELECT id, server_id, title, mode, created_at, updated_at, last_message_at
                FROM chat_sessions
                WHERE {where_clause}
                ORDER BY last_message_at DESC NULLS LAST, created_at DESC
                LIMIT 200
                """
            ),
            params,
        ).mappings().all()
    return [dict(row) for row in rows]


def _get_session(*, user_id: UUID, session_id: UUID) -> dict[str, Any]:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, user_id, server_id, title, mode, created_at, updated_at, last_message_at
                FROM chat_sessions
                WHERE id = :session_id AND user_id = :user_id
                """
            ),
            {"session_id": str(session_id), "user_id": str(user_id)},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Chat session not found", status_code=404)
    return dict(row)


def list_chat_messages(*, user_id: UUID, session_id: UUID, limit: int) -> list[dict[str, Any]]:
    _get_session(user_id=user_id, session_id=session_id)
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, session_id, role, content, created_at
                FROM chat_messages
                WHERE session_id = :session_id
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
                """
            ),
            {"session_id": str(session_id), "limit": limit},
        ).mappings().all()
    return [dict(row) for row in reversed(rows)]


def _get_recent_conversation(*, session_id: UUID, limit: int = 20) -> list[dict[str, str]]:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT role, content
                FROM chat_messages
                WHERE session_id = :session_id
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
                """
            ),
            {"session_id": str(session_id), "limit": limit},
        ).mappings().all()

    messages: list[dict[str, str]] = []
    for row in reversed(rows):
        role = str(row.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = str(row.get("content") or "").strip()
        if not content:
            continue
        messages.append({"role": role, "content": content})
    return messages


def _fetch_recent_app_events(*, user_id: UUID, server_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
    """Fetch recent app events for a server to include in chat context."""
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT source, event, severity, meta, ip, created_at
                FROM app_events
                WHERE user_id = :user_id AND server_id = :server_id
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"user_id": str(user_id), "server_id": str(server_id), "limit": limit},
        ).mappings().all()
    result = []
    for row in rows:
        meta = row.get("meta")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                pass
        result.append({
            "ts": str(row.get("created_at") or ""),
            "source": row.get("source"),
            "event": row.get("event"),
            "severity": row.get("severity"),
            "meta": meta if isinstance(meta, dict) else {},
            "ip": row.get("ip"),
        })
    return result


def _build_server_context(*, user_id: UUID, server_id: UUID) -> dict[str, Any]:
    settings = get_settings()
    packet = build_chat_context_packet(user_id=user_id, server_id=server_id)
    recent_alerts = packet.get("alerts") if isinstance(packet.get("alerts"), list) else []
    unresolved_alerts = [a for a in recent_alerts if not bool(a.get("is_resolved"))]

    packet_logs = packet.get("logs") if isinstance(packet.get("logs"), dict) else {}
    flat_logs: list[dict[str, Any]] = []
    for source_name, rows in packet_logs.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            flat_logs.append(
                {
                    "ts": row.get("ts"),
                    "source": row.get("source") or source_name,
                    "level": row.get("level", "unknown"),
                    "message": row.get("message", ""),
                }
            )
    flat_logs.sort(key=lambda item: str(item.get("ts") or ""), reverse=True)
    log_limit = max(1, int(settings.chat_context_logs_total_limit))

    docker_containers = packet.get("docker_containers") if isinstance(packet.get("docker_containers"), list) else []

    snapshot = packet.get("metrics_snapshot") if isinstance(packet.get("metrics_snapshot"), dict) else {}
    metrics = [snapshot] if snapshot else []

    server = packet.get("server") if isinstance(packet.get("server"), dict) else {}
    identity = packet.get("identity") if isinstance(packet.get("identity"), dict) else {}
    capabilities = (
        packet.get("agent_capabilities")
        if isinstance(packet.get("agent_capabilities"), dict)
        else {}
    )

    app_events = _fetch_recent_app_events(user_id=user_id, server_id=server_id, limit=50)

    return {
        "server": {
            "id": str(server.get("id") or server_id),
            "name": server.get("name"),
            "status": server.get("status"),
            "last_seen_at": server.get("last_seen_at"),
            "created_at": server.get("created_at"),
            "metadata": {
                "host": identity,
                "docker_containers": docker_containers,
                "agent_capabilities": capabilities,
            },
        },
        "metrics": metrics,
        "alerts": {
            "unresolved_count": len(unresolved_alerts),
            "recent_count": len(recent_alerts),
            "unresolved": unresolved_alerts[:20],
            "recent": recent_alerts[:30],
        },
        "logs": flat_logs[:log_limit],
        "app_events": app_events,
        "uptime_monitors": [],
        "troubleshooting_packet": packet,
    }


def _build_system_prompt() -> str:
    suggest_only = get_settings().llm_suggest_only
    mode_line = "SUGGEST-ONLY mode is ON." if suggest_only else "SUGGEST-ONLY mode is OFF."
    return (
        "You are DevOps Assistant for production troubleshooting.\n"
        f"{mode_line}\n"
        "Primary objective:\n"
        "- Diagnose the user's issue using the provided server context (metrics, alerts, logs, docker, host metadata, uptime, app events).\n"
        "- Give the shortest high-confidence path to mitigation without unsafe actions.\n\n"
        "Data sources in context JSON:\n"
        "- `server`: server identity, status, host info, docker containers, agent capabilities\n"
        "- `metrics`: CPU, RAM, disk, load average, network usage\n"
        "- `alerts`: unresolved and recent alerts with type, severity, details\n"
        "- `logs`: system logs from systemd, nginx, docker (with source, level, message)\n"
        "- `app_events`: application-level events sent by the user's app via ServerNotify SDK. "
        "Each event has: ts (timestamp), source (e.g. auth-service, payment-service), "
        "event (e.g. login_failed, payment_success, api_error), severity (info/warning/error), "
        "meta (dict with details like user_id, ip, reason, amount), and ip. "
        "Use app_events to answer questions about application behavior, login patterns, "
        "payment failures, error rates, security issues, and user activity. "
        "When the user asks about app events, summarize counts, patterns, and notable entries.\n"
        "- `uptime_monitors`: HTTP endpoint monitoring data\n\n"
        "Hard rules:\n"
        "- Never claim you executed commands or changed server state.\n"
        "- Do not provide generic boilerplate answers. Tailor output to the actual evidence in context.\n"
        "- If evidence is insufficient or conflicting, explicitly say what is missing.\n"
        "- Prefer reversible, low-risk steps first and include verification after each major step.\n"
        "- If a component has no evidence (for example no docker symptoms), do not force docker fixes.\n"
        "- Use concrete values/timestamps from context when available (CPU, RAM, disk, alert type, log lines, status, app event details).\n"
        "- Do not suggest destructive commands by default (no `rm -rf`, data deletion, dropping databases, or force resets).\n"
        "- Do not ask user to disable firewall or run untrusted `curl | bash` commands.\n"
        "- For config-changing suggestions, always include rollback notes.\n"
        "- Reply in the same language used by the user.\n\n"
        "Reasoning style:\n"
        "- Build a hypothesis tree, rank top causes by likelihood, then propose checks that disambiguate causes.\n"
        "- Keep command count focused; avoid large shotgun command lists.\n"
        "- Include expected command outcomes so user knows what confirms or rejects a hypothesis.\n"
        "- When answering about app events, group by event type, count occurrences, highlight patterns (e.g. spike in login_failed from same IP).\n\n"
        "Response format (use when troubleshooting — for simple questions about data, just answer directly):\n"
        "1) What I see (evidence)\n"
        "2) Most likely root cause\n"
        "3) Checks to run now (ordered)\n"
        "4) Safe fix plan (ordered)\n"
        "5) Verification\n"
        "6) Risks and rollback\n"
    )


_SEVERITY_COLORS = {"info": "#3b82f6", "warning": "#f59e0b", "error": "#ef4444"}
_EVENT_COLORS = [
    "#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6",
    "#ec4899", "#06b6d4", "#f97316", "#14b8a6", "#6366f1",
]

_EVENT_KEYWORDS = [
    "event", "events", "login", "payment", "error", "signup",
    "activity", "security", "app_event", "app event",
    "احداث", "اخطاء", "تسجيل", "دفع", "نشاط",
]


def _should_show_event_charts(user_message: str) -> bool:
    """Detect if user is asking about app events."""
    msg = user_message.lower()
    return any(kw in msg for kw in _EVENT_KEYWORDS)


def _build_charts_from_context(context: dict[str, Any], user_message: str) -> list[dict[str, Any]]:
    """Build charts from context data based on what the user asked about."""
    charts: list[dict[str, Any]] = []
    app_events = context.get("app_events") or []

    if _should_show_event_charts(user_message) and app_events:
        # Chart 1: Events by type (bar)
        event_counts: dict[str, int] = {}
        for ev in app_events:
            name = ev.get("event") or "unknown"
            event_counts[name] = event_counts.get(name, 0) + 1
        if event_counts:
            sorted_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            charts.append({
                "chart_type": "bar",
                "title": "Events by Type",
                "x_label": "Event",
                "y_label": "Count",
                "data": [
                    {"label": name, "value": float(count), "color": _EVENT_COLORS[i % len(_EVENT_COLORS)]}
                    for i, (name, count) in enumerate(sorted_events)
                ],
            })

        # Chart 2: Events by severity (doughnut)
        sev_counts: dict[str, int] = {}
        for ev in app_events:
            sev = ev.get("severity") or "info"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev_counts:
            charts.append({
                "chart_type": "doughnut",
                "title": "Events by Severity",
                "data": [
                    {"label": sev, "value": float(count), "color": _SEVERITY_COLORS.get(sev, "#6b7280")}
                    for sev, count in sorted(sev_counts.items())
                ],
            })

        # Chart 3: Events by source (pie)
        source_counts: dict[str, int] = {}
        for ev in app_events:
            src = ev.get("source") or "unknown"
            source_counts[src] = source_counts.get(src, 0) + 1
        if len(source_counts) > 1:
            sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            charts.append({
                "chart_type": "pie",
                "title": "Events by Source",
                "data": [
                    {"label": src, "value": float(count), "color": _EVENT_COLORS[i % len(_EVENT_COLORS)]}
                    for i, (src, count) in enumerate(sorted_sources)
                ],
            })

    # Metrics charts (when asking about CPU, RAM, disk, etc.)
    metrics = context.get("metrics") or []
    msg_lower = user_message.lower()
    metric_keywords = ["cpu", "ram", "memory", "disk", "load", "metric", "performance", "مؤشر", "ذاكرة", "معالج"]
    if any(kw in msg_lower for kw in metric_keywords) and metrics:
        m = metrics[0] if metrics else {}
        cpu = m.get("cpu_percent") or m.get("cpu_avg")
        ram = m.get("ram_percent") or m.get("ram_avg")
        disk = m.get("disk_percent") or m.get("disk_avg")
        if cpu is not None or ram is not None or disk is not None:
            data = []
            if cpu is not None:
                color = "#ef4444" if float(cpu) > 80 else "#f59e0b" if float(cpu) > 60 else "#10b981"
                data.append({"label": "CPU", "value": float(cpu), "color": color})
            if ram is not None:
                color = "#ef4444" if float(ram) > 80 else "#f59e0b" if float(ram) > 60 else "#10b981"
                data.append({"label": "RAM", "value": float(ram), "color": color})
            if disk is not None:
                color = "#ef4444" if float(disk) > 85 else "#f59e0b" if float(disk) > 70 else "#10b981"
                data.append({"label": "Disk", "value": float(disk), "color": color})
            if data:
                charts.append({
                    "chart_type": "bar",
                    "title": "Current Resource Usage (%)",
                    "x_label": "Resource",
                    "y_label": "Usage %",
                    "data": data,
                })

    return charts


def ask_chat_assistant(
    *,
    user_id: UUID,
    session_id: UUID,
    user_message: str,
) -> dict[str, Any]:
    session = _get_session(user_id=user_id, session_id=session_id)

    with get_engine().begin() as conn:
        user_row = conn.execute(
            text(
                """
                INSERT INTO chat_messages (session_id, user_id, role, content)
                VALUES (:session_id, :user_id, 'user', :content)
                RETURNING id, session_id, role, content, created_at
                """
            ),
            {"session_id": str(session_id), "user_id": str(user_id), "content": user_message},
        ).mappings().one()
        conn.execute(
            text(
                """
                UPDATE chat_sessions
                SET updated_at = now(),
                    last_message_at = now()
                WHERE id = :session_id
                  AND user_id = :user_id
                """
            ),
            {"session_id": str(session_id), "user_id": str(user_id)},
        )

    context = _build_server_context(user_id=user_id, server_id=session["server_id"])
    conversation = _get_recent_conversation(session_id=session_id, limit=20)
    assistant_text, model_used = generate_assistant_reply(
        system_prompt=_build_system_prompt(),
        context=context,
        conversation=conversation,
    )

    context_snapshot = {
        "server_id": context["server"]["id"],
        "server_name": context["server"]["name"],
        "server_status": context["server"]["status"],
        "unresolved_alerts": context["alerts"]["unresolved_count"],
        "recent_logs": len(context["logs"]),
        "app_events": len(context.get("app_events") or []),
    }
    with get_engine().begin() as conn:
        assistant_row = conn.execute(
            text(
                """
                INSERT INTO chat_messages (session_id, user_id, role, content, context_snapshot)
                VALUES (:session_id, NULL, 'assistant', :content, CAST(:context_snapshot AS jsonb))
                RETURNING id, session_id, role, content, created_at
                """
            ),
            {
                "session_id": str(session_id),
                "content": assistant_text,
                "context_snapshot": json.dumps(context_snapshot, separators=(",", ":")),
            },
        ).mappings().one()
        conn.execute(
            text(
                """
                UPDATE chat_sessions
                SET updated_at = now(),
                    last_message_at = now()
                WHERE id = :session_id
                  AND user_id = :user_id
                """
            ),
            {"session_id": str(session_id), "user_id": str(user_id)},
        )

    charts = _build_charts_from_context(context, user_message)

    return {
        "session_id": session_id,
        "mode": "suggest_only",
        "model": model_used,
        "user_message": dict(user_row),
        "assistant_message": dict(assistant_row),
        "charts": charts,
    }
