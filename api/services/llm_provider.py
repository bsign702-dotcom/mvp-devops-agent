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


def _mock_reply(*, user_prompt: str) -> str:
    return (
        "Diagnosis\n"
        "- Based on the provided context, the issue is likely caused by service instability or resource pressure.\n\n"
        "Checks to run\n"
        "- `systemctl status nginx --no-pager`\n"
        "- `docker ps -a --format \"table {{.Names}}\\t{{.Status}}\"`\n"
        "- `df -h`\n"
        "- `free -m`\n\n"
        "Safe fix plan\n"
        "- Confirm failing unit/container from logs.\n"
        "- Fix root cause (disk cleanup, config rollback, cert renew, restart failed service).\n"
        "- Re-check health endpoints and error rates.\n\n"
        "Commands\n"
        "- `journalctl -u nginx -n 200 --no-pager`\n"
        "- `sudo systemctl restart nginx`\n"
        "- `docker logs <container> --tail 200`\n\n"
        "Notes\n"
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
        return _mock_reply(user_prompt=last_user_prompt), "mock-devops-v1"

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
        "temperature": 0.1,
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
