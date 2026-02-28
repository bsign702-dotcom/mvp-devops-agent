from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text

from ..db import get_engine
from ..errors import APIError
from ..settings import get_settings
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


def _build_server_context(*, user_id: UUID, server_id: UUID) -> dict[str, Any]:
    with get_engine().connect() as conn:
        server = conn.execute(
            text(
                """
                SELECT id, name, status, last_seen_at, created_at, metadata
                FROM servers
                WHERE id = :server_id
                  AND user_id = :user_id
                """
            ),
            {"server_id": str(server_id), "user_id": str(user_id)},
        ).mappings().first()
        if not server:
            raise APIError(code="not_found", message="Server not found", status_code=404)

        metrics_rows = conn.execute(
            text(
                """
                SELECT ts, cpu_percent, ram_percent, disk_percent, load1, load5, load15, net_bytes_sent, net_bytes_recv
                FROM metrics
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 20
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        unresolved_alerts = conn.execute(
            text(
                """
                SELECT ts, type, severity, title, details
                FROM alerts
                WHERE user_id = :user_id
                  AND server_id = :server_id
                  AND is_resolved = false
                ORDER BY ts DESC
                LIMIT 20
                """
            ),
            {"user_id": str(user_id), "server_id": str(server_id)},
        ).mappings().all()

        recent_alerts = conn.execute(
            text(
                """
                SELECT ts, type, severity, title, details, is_resolved, resolved_at
                FROM alerts
                WHERE user_id = :user_id
                  AND server_id = :server_id
                ORDER BY ts DESC
                LIMIT 40
                """
            ),
            {"user_id": str(user_id), "server_id": str(server_id)},
        ).mappings().all()

        recent_logs = conn.execute(
            text(
                """
                SELECT ts, source, level, message
                FROM logs
                WHERE server_id = :server_id
                  AND level IN ('warn', 'error')
                ORDER BY ts DESC
                LIMIT 80
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        uptime_rows = conn.execute(
            text(
                """
                SELECT id, name, url, last_status, last_response_time_ms, consecutive_failures, last_checked_at
                FROM uptime_monitors
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                LIMIT 20
                """
            ),
            {"user_id": str(user_id)},
        ).mappings().all()

    metadata = _normalize_json(server.get("metadata")) or {}
    if not isinstance(metadata, dict):
        metadata = {"raw": metadata}

    metrics = [dict(row) for row in reversed(metrics_rows)]
    unresolved = [
        {**dict(row), "details": _normalize_json(row.get("details"))}
        for row in unresolved_alerts
    ]
    recent = [
        {**dict(row), "details": _normalize_json(row.get("details"))}
        for row in recent_alerts
    ]
    logs = [dict(row) for row in recent_logs]
    uptime = [dict(row) for row in uptime_rows]

    return {
        "server": {
            "id": str(server["id"]),
            "name": server["name"],
            "status": server["status"],
            "last_seen_at": server["last_seen_at"],
            "created_at": server["created_at"],
            "metadata": metadata,
        },
        "metrics": metrics,
        "alerts": {
            "unresolved_count": len(unresolved),
            "recent_count": len(recent),
            "unresolved": unresolved[:20],
            "recent": recent[:30],
        },
        "logs": logs[:60],
        "uptime_monitors": uptime,
    }


def _build_system_prompt() -> str:
    suggest_only = get_settings().llm_suggest_only
    mode_line = "SUGGEST-ONLY mode is ON." if suggest_only else "SUGGEST-ONLY mode is OFF."
    return (
        "You are DevOps Assistant for production troubleshooting.\n"
        f"{mode_line}\n"
        "Primary objective:\n"
        "- Diagnose the user's issue using the provided server context (metrics, alerts, logs, docker, host metadata, uptime).\n"
        "- Give the shortest high-confidence path to mitigation without unsafe actions.\n\n"
        "Hard rules:\n"
        "- Never claim you executed commands or changed server state.\n"
        "- Do not provide generic boilerplate answers. Tailor output to the actual evidence in context.\n"
        "- If evidence is insufficient or conflicting, explicitly say what is missing.\n"
        "- Prefer reversible, low-risk steps first and include verification after each major step.\n"
        "- If a component has no evidence (for example no docker symptoms), do not force docker fixes.\n"
        "- Use concrete values/timestamps from context when available (CPU, RAM, disk, alert type, log lines, status).\n"
        "- Reply in the same language used by the user.\n\n"
        "Reasoning style:\n"
        "- Build a hypothesis tree, rank top causes by likelihood, then propose checks that disambiguate causes.\n"
        "- Keep command count focused; avoid large shotgun command lists.\n"
        "- Include expected command outcomes so user knows what confirms or rejects a hypothesis.\n\n"
        "Response format:\n"
        "1) What I see (evidence)\n"
        "2) Most likely root cause\n"
        "3) Checks to run now (ordered)\n"
        "4) Safe fix plan (ordered)\n"
        "5) Verification\n"
        "6) Risks and rollback\n"
    )


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

    return {
        "session_id": session_id,
        "mode": "suggest_only",
        "model": model_used,
        "user_message": dict(user_row),
        "assistant_message": dict(assistant_row),
    }
