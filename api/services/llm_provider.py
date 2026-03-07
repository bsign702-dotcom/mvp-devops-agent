from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..errors import APIError
from ..settings import get_settings

logger = logging.getLogger(__name__)


def _trim_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max(0, max_chars - 20)] + "\n...[truncated]"


def _to_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _to_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _short(value: Any, max_chars: int = 180) -> str:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _mock_reply(*, user_prompt: str, context: dict[str, Any]) -> str:
    server = _to_dict(context.get("server"))
    metadata = _to_dict(server.get("metadata"))
    host = _to_dict(metadata.get("host"))
    metrics = _to_list(context.get("metrics"))
    latest_metric = _to_dict(metrics[-1] if metrics else {})
    alerts = _to_dict(context.get("alerts"))
    unresolved_alerts = _to_list(alerts.get("unresolved"))
    logs = _to_list(context.get("logs"))
    uptime_monitors = _to_list(context.get("uptime_monitors"))
    docker_containers = _to_list(metadata.get("docker_containers")) or _to_list(context.get("docker_containers"))

    cpu = latest_metric.get("cpu_percent")
    ram = latest_metric.get("ram_percent")
    disk = latest_metric.get("disk_percent")

    high_cpu = isinstance(cpu, (int, float)) and cpu >= 85
    high_ram = isinstance(ram, (int, float)) and ram >= 90
    high_disk = isinstance(disk, (int, float)) and disk >= 90

    recent_log_lines: list[str] = []
    has_nginx_errors = False
    has_docker_errors = False
    for item in logs[:6]:
        row = _to_dict(item)
        source = str(row.get("source") or "unknown").strip().lower()
        message = _short(row.get("message"), 140)
        if not message:
            continue
        recent_log_lines.append(f"- [{source}] {message}")
        lower = message.lower()
        if source == "nginx" or "nginx" in lower:
            has_nginx_errors = True
        if source == "docker" or any(k in lower for k in ["crashloop", "restart", "exited", "container"]):
            has_docker_errors = True

    unstable_containers = []
    for container in docker_containers[:10]:
        row = _to_dict(container)
        status = str(row.get("status") or "").lower()
        if any(token in status for token in ["restart", "exited", "unhealthy"]):
            unstable_containers.append(
                {
                    "name": str(row.get("name") or row.get("id") or "container"),
                    "status": str(row.get("status") or ""),
                }
            )

    monitor_failures = [
        _to_dict(m)
        for m in uptime_monitors
        if str(_to_dict(m).get("last_status") or "").lower() != "up"
    ]

    alert_types = [str(_to_dict(a).get("type") or "").strip().lower() for a in unresolved_alerts[:20]]
    hypothesis = "service instability"
    if high_disk or "disk_high" in alert_types or any("no space" in str(line).lower() for line in recent_log_lines):
        hypothesis = "disk pressure / low free space"
    elif has_nginx_errors:
        hypothesis = "nginx upstream/config/runtime failure"
    elif unstable_containers or has_docker_errors:
        hypothesis = "docker container instability (restart/crash)"
    elif monitor_failures:
        hypothesis = "uptime failures (service unavailable or network/SSL issue)"
    elif high_cpu or high_ram:
        hypothesis = "resource saturation (CPU/RAM)"

    evidence_lines = [
        f"- Server: `{server.get('name', 'unknown')}` status=`{server.get('status', 'unknown')}` last_seen=`{server.get('last_seen_at', '-')}`"
    ]
    if host.get("primary_ip"):
        evidence_lines.append(f"- Primary IP: `{host['primary_ip']}`")
    domains = _to_list(host.get("domains"))
    if domains:
        evidence_lines.append(f"- Domains: {', '.join(f'`{d}`' for d in domains[:3])}")
    if latest_metric:
        evidence_lines.append(
            f"- Latest metrics: CPU={cpu}%, RAM={ram}%, Disk={disk}%"
        )
    if unresolved_alerts:
        for alert in unresolved_alerts[:3]:
            a = _to_dict(alert)
            evidence_lines.append(
                f"- Alert: `{a.get('type', 'unknown')}` severity=`{a.get('severity', '-')}` title=`{_short(a.get('title'), 90)}`"
            )
    if recent_log_lines:
        evidence_lines.append("- Recent logs:")
        evidence_lines.extend(recent_log_lines[:4])

    checks: list[str] = []
    fixes: list[str] = []
    commands: list[str] = []

    if hypothesis == "disk pressure / low free space":
        checks = [
            "Confirm which mount is full and largest directories.",
            "Check whether logs or docker layers are the main consumer.",
        ]
        fixes = [
            "Free space using low-risk cleanup (old logs, dangling images, old artifacts).",
            "Rotate/compress logs, then verify disk drops below threshold.",
        ]
        commands = [
            "`df -h`",
            "`sudo du -xhd1 /var | sort -h`",
            "`docker system df`",
            "`sudo journalctl --vacuum-time=7d`",
        ]
    elif hypothesis == "nginx upstream/config/runtime failure":
        checks = [
            "Validate nginx config and identify failing upstream from error logs.",
            "Verify app/upstream health endpoint from the server itself.",
        ]
        fixes = [
            "Fix upstream connectivity/config mismatch, then reload nginx.",
            "If needed, rollback the latest nginx/app config change.",
        ]
        commands = [
            "`sudo nginx -t`",
            "`sudo tail -n 200 /var/log/nginx/error.log`",
            "`curl -I http://127.0.0.1`",
            "`sudo systemctl reload nginx`",
        ]
    elif hypothesis == "docker container instability (restart/crash)":
        checks = [
            "Identify which containers are restarting and inspect their latest errors.",
            "Validate dependency readiness (DB/Redis/network/env secrets).",
        ]
        fixes = [
            "Fix root cause from logs (config, env var, dependency, image mismatch).",
            "Restart only affected containers, then verify stability for at least 5-10 minutes.",
        ]
        commands = [
            "`docker ps -a --format \"table {{.Names}}\\t{{.Status}}\"`",
            "`docker logs <container_name> --tail 200`",
            "`docker inspect <container_name> --format '{{json .State}}'`",
        ]
    elif hypothesis == "uptime failures (service unavailable or network/SSL issue)":
        checks = [
            "Check failing monitor targets and status codes/timeouts.",
            "Validate DNS/TLS expiry and backend reachability.",
        ]
        fixes = [
            "Resolve DNS/TLS or upstream reachability issue, then re-check monitor status.",
            "Increase timeout only if service is healthy but consistently slow.",
        ]
        commands = [
            "`curl -Iv <monitor_url>`",
            "`openssl s_client -connect <domain>:443 -servername <domain> </dev/null | openssl x509 -noout -dates`",
        ]
    else:
        checks = [
            "Correlate latest alerts with warn/error logs around the same timestamp.",
            "Check service status and resource headroom before restarting anything.",
        ]
        fixes = [
            "Apply the smallest reversible fix first, then re-check metrics and alerts.",
            "If still failing, isolate by service (nginx/app/db/docker) and repeat.",
        ]
        commands = [
            "`systemctl --failed`",
            "`free -m`",
            "`df -h`",
            "`docker ps -a --format \"table {{.Names}}\\t{{.Status}}\"`",
        ]

    if unstable_containers:
        unstable_text = ", ".join(
            f"`{c['name']}` ({c['status']})" for c in unstable_containers[:3]
        )
        evidence_lines.append(f"- Unstable containers: {unstable_text}")

    verification = [
        "Confirm alert count drops and no new critical logs appear for 10 minutes.",
        "Validate primary health endpoint returns expected status consistently.",
    ]
    risks = [
        "Service restart may cause brief downtime.",
        "Log cleanup can remove forensic data if done aggressively.",
    ]
    rollback = [
        "Revert latest config/deployment change.",
        "Restore previous service/container version if errors persist.",
    ]

    return (
        "1) What I see (evidence)\n"
        + "\n".join(evidence_lines[:10])
        + "\n\n2) Most likely root cause\n"
        + f"- {hypothesis}\n"
        + "\n3) Checks to run now (ordered)\n"
        + "\n".join(f"- {line}" for line in checks[:4])
        + "\n\n4) Safe fix plan (ordered)\n"
        + "\n".join(f"- {line}" for line in fixes[:4])
        + "\n\n5) Verification\n"
        + "\n".join(f"- {line}" for line in verification)
        + "\n\n6) Risks and rollback\n"
        + "\n".join(f"- Risk: {line}" for line in risks)
        + "\n"
        + "\n".join(f"- Rollback: {line}" for line in rollback)
        + "\n\nCommands (copy/paste)\n"
        + "\n".join(f"- {cmd}" for cmd in commands[:6])
        + "\n\nNotes\n"
        "- This is suggest-only guidance. No command was executed by AI.\n"
        f"- User question: {user_prompt}"
    )


def generate_assistant_reply(
    *,
    system_prompt: str,
    context: dict[str, Any],
    conversation: list[dict[str, str]],
) -> tuple[str, str]:
    settings = get_settings()
    provider = settings.llm_provider.strip().lower()
    model = settings.llm_model.strip()
    if not model:
        raise APIError(code="server_error", message="LLM_MODEL is empty", status_code=500)

    last_user_prompt = ""
    for msg in reversed(conversation):
        if msg.get("role") == "user":
            last_user_prompt = msg.get("content", "")
            break

    if provider == "mock":
        return _mock_reply(user_prompt=last_user_prompt, context=context), "mock-devops-v2"

    if provider != "openai":
        raise APIError(
            code="bad_request",
            message="Unsupported LLM provider",
            status_code=400,
            details={"provider": provider, "supported": ["openai", "mock"]},
        )

    if not settings.openai_api_key:
        raise APIError(
            code="bad_request",
            message="OpenAI API key is not configured",
            status_code=400,
            details={"required": ["OPENAI_API_KEY"]},
        )

    context_json = json.dumps(context, default=str, separators=(",", ":"))
    context_json = _trim_text(context_json, max(4000, settings.llm_max_context_chars))
    composed_system_prompt = (
        f"{system_prompt}\n\n"
        "Server context JSON follows. Use it as factual input.\n"
        f"{context_json}"
    )

    messages: list[dict[str, str]] = [{"role": "system", "content": composed_system_prompt}]
    for msg in conversation[-20:]:
        role = str(msg.get("role") or "").strip().lower()
        content = str(msg.get("content") or "").strip()
        if role not in {"user", "assistant"} or not content:
            continue
        messages.append({"role": role, "content": content})

    url = settings.openai_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    }

    try:
        with httpx.Client(timeout=httpx.Timeout(settings.llm_timeout_sec)) as client:
            resp = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise APIError(
            code="server_error",
            message="Failed to reach LLM provider",
            status_code=500,
            details={"provider": provider, "error": str(exc)},
        ) from exc

    if resp.status_code in (401, 403):
        raise APIError(
            code="server_error",
            message="LLM provider authentication failed",
            status_code=500,
            details={"provider": provider, "status_code": resp.status_code},
        )
    if resp.status_code >= 400:
        response_preview = _trim_text(resp.text or "", 800)
        raise APIError(
            code="server_error",
            message="LLM provider returned an error",
            status_code=500,
            details={"provider": provider, "status_code": resp.status_code, "response": response_preview},
        )

    try:
        payload = resp.json()
        content = payload["choices"][0]["message"]["content"]
    except Exception as exc:
        raise APIError(
            code="server_error",
            message="Invalid LLM response payload",
            status_code=500,
            details={"provider": provider},
        ) from exc

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text_part = item.get("text")
                if isinstance(text_part, str):
                    parts.append(text_part)
        content = "\n".join(parts)
    if not isinstance(content, str):
        content = str(content)
    content = content.strip()
    if not content:
        content = "No response generated by the assistant."

    logger.info(
        "llm_response_generated",
        extra={"event": "llm_response_generated", "provider": provider, "model": model},
    )
    return content, model


# ---------------------------------------------------------------------------
# AI Event Generator
# ---------------------------------------------------------------------------

_EVENT_GENERATOR_SYSTEM_PROMPT = """You are ServerNotify AI — an expert analytics event engineer.

The developer describes an app event in plain language (any language including Arabic), and you generate everything they need.

RULES:
1. EVENT NAMING: Always use snake_case. Prefix with category when helpful (e.g. auth_login). Keep names short and clear.
2. PARAMETERS: Suggest 3-7 practical parameters. Always include user_id if applicable. Use types: String, Int, Double, Boolean, Date. Mark required vs optional. Add realistic example values.
3. CODE: Generate production-ready code using the ServerNotify HTTP API pattern:
   POST https://omcard.net/v1/events
   Headers: Authorization: Bearer APP_KEY, Content-Type: application/json
   Body: {"source": "...", "event": "...", "severity": "info|warning|error", "meta": {...}}
   Always wrap in try/catch with comment "Never break your app because of monitoring"
4. SUGGESTIONS: Suggest 2-3 related events the developer should also track.
5. Always output in English regardless of input language.
6. Events should follow industry standards (GA4, Mixpanel, Amplitude patterns).
7. severity must be exactly one of: "info", "warning", "error"

Respond ONLY in valid JSON with this exact structure — no markdown, no backticks, no preamble:
{
  "event_name": "snake_case_name",
  "display_name": "Human Readable Name",
  "category": "Category",
  "description": "Brief description",
  "severity": "info",
  "suggested_source": "service-name",
  "parameters": [
    {"name": "param_name", "type": "String", "description": "What this tracks", "example": "example_value", "required": true}
  ],
  "code": {
    "platform_key": "// Full tracking code for that platform"
  },
  "suggestions": ["related_event_1", "related_event_2"]
}

Generate code ONLY for the platforms listed in the user request. Platform keys: python, node, php, ruby, go, curl, swift, kotlin, flutter, react_native, web_js"""


def generate_event_definition(
    *,
    description: str,
    platforms: list[str],
) -> dict[str, Any]:
    """Use LLM to generate a structured event definition from a plain-language description."""
    settings = get_settings()
    provider = settings.llm_provider.strip().lower()
    model = settings.llm_model.strip()

    if not model:
        raise APIError(code="server_error", message="LLM_MODEL is empty", status_code=500)

    if provider == "mock":
        return {
            "event_name": "mock_event",
            "display_name": "Mock Event",
            "category": "Custom",
            "description": description,
            "severity": "info",
            "suggested_source": "app",
            "parameters": [
                {"name": "user_id", "type": "String", "description": "User identifier", "example": "usr_123", "required": True},
            ],
            "code": {p: f"// Mock code for {p}" for p in platforms},
            "suggestions": ["related_event"],
        }

    if provider != "openai":
        raise APIError(
            code="bad_request", message="Unsupported LLM provider", status_code=400,
            details={"provider": provider, "supported": ["openai", "mock"]},
        )

    if not settings.openai_api_key:
        raise APIError(
            code="bad_request", message="OpenAI API key is not configured", status_code=400,
        )

    user_msg = f"Description: {description}\nPlatforms: {', '.join(platforms)}"

    url = settings.openai_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _EVENT_GENERATOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.3,
    }

    try:
        with httpx.Client(timeout=httpx.Timeout(settings.llm_timeout_sec)) as client:
            resp = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise APIError(
            code="server_error", message="Failed to reach LLM provider", status_code=500,
            details={"error": str(exc)},
        ) from exc

    if resp.status_code >= 400:
        raise APIError(
            code="server_error", message="LLM provider returned an error", status_code=500,
            details={"status_code": resp.status_code},
        )

    try:
        payload = resp.json()
        content = payload["choices"][0]["message"]["content"]
    except Exception as exc:
        raise APIError(
            code="server_error", message="Invalid LLM response payload", status_code=500,
        ) from exc

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text_part = item.get("text")
                if isinstance(text_part, str):
                    parts.append(text_part)
        content = "\n".join(parts)
    if not isinstance(content, str):
        content = str(content)
    content = content.strip()

    # Strip markdown fences if the LLM wrapped the JSON
    if content.startswith("```"):
        lines = content.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        content = "\n".join(lines).strip()

    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        raise APIError(
            code="server_error", message="LLM returned invalid JSON", status_code=500,
            details={"raw": _trim_text(content, 500)},
        )

    # Ensure severity is valid
    if result.get("severity") not in ("info", "warning", "error"):
        result["severity"] = "info"

    # Coerce parameter fields to strings (LLM may return numbers)
    for param in result.get("parameters") or []:
        if isinstance(param, dict):
            for key in ("name", "type", "description", "example"):
                if key in param and not isinstance(param[key], str):
                    param[key] = str(param[key])

    logger.info(
        "event_definition_generated",
        extra={"event": "event_definition_generated", "provider": provider, "model": model, "event_name": result.get("event_name")},
    )
    return result
