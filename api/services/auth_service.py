from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
from fastapi import Request
from sqlalchemy import text

from ..db import get_engine
from ..errors import APIError
from ..settings import get_settings
from .admin_notify_service import notify_new_user_created

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AuthenticatedUser:
    local_user_id: UUID
    supabase_user_id: UUID
    email: str
    full_name: str | None
    metadata: dict[str, Any]
    raw_supabase_user: dict[str, Any]


async def require_authenticated_user(request: Request) -> AuthenticatedUser:
    token = _extract_bearer_token(request)
    supabase_user = await _fetch_supabase_user(token)
    return await asyncio.to_thread(_upsert_local_user, supabase_user)


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise APIError(code="unauthorized", message="Missing bearer token", status_code=401)
    token = auth_header[len("Bearer ") :].strip()
    if not token:
        raise APIError(code="unauthorized", message="Missing bearer token", status_code=401)
    return token


async def _fetch_supabase_user(access_token: str) -> dict[str, Any]:
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_anon_key:
        raise APIError(
            code="server_error",
            message="Supabase auth is not configured on backend",
            status_code=500,
            details={"required": ["SUPABASE_URL", "SUPABASE_ANON_KEY"]},
        )

    base = settings.supabase_url.rstrip("/")
    url = f"{base}/auth/v1/user"
    timeout = httpx.Timeout(settings.supabase_auth_timeout_sec)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "apikey": settings.supabase_anon_key,
                },
            )
    except httpx.HTTPError as exc:
        raise APIError(
            code="server_error",
            message="Failed to reach Supabase auth",
            status_code=500,
            details={"error": str(exc)},
        ) from exc

    if resp.status_code in (401, 403):
        raise APIError(code="unauthorized", message="Invalid or expired auth token", status_code=401)
    if resp.status_code >= 500:
        raise APIError(
            code="server_error",
            message="Supabase auth server error",
            status_code=500,
            details={"status_code": resp.status_code},
        )
    if resp.status_code != 200:
        raise APIError(
            code="unauthorized",
            message="Unable to validate auth token",
            status_code=401,
            details={"status_code": resp.status_code},
        )

    try:
        payload = resp.json()
    except Exception as exc:
        raise APIError(code="server_error", message="Invalid Supabase auth response", status_code=500) from exc

    if not isinstance(payload, dict):
        raise APIError(code="server_error", message="Invalid Supabase user payload", status_code=500)
    if not payload.get("id") or not payload.get("email"):
        raise APIError(code="unauthorized", message="Supabase token missing user identity", status_code=401)
    return payload


def _upsert_local_user(supabase_user: dict[str, Any]) -> AuthenticatedUser:
    try:
        supabase_user_id = str(supabase_user["id"])
        email = str(supabase_user["email"]).strip().lower()
    except KeyError as exc:
        raise APIError(code="unauthorized", message="Supabase user payload incomplete", status_code=401) from exc

    user_metadata = supabase_user.get("user_metadata") or {}
    app_metadata = supabase_user.get("app_metadata") or {}
    full_name = None
    if isinstance(user_metadata, dict):
        full_name = user_metadata.get("full_name") or user_metadata.get("name")
    if full_name is not None:
        full_name = str(full_name).strip() or None

    metadata = {
        "user_metadata": user_metadata if isinstance(user_metadata, dict) else {},
        "app_metadata": app_metadata if isinstance(app_metadata, dict) else {},
    }

    with get_engine().begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO users (
                    supabase_user_id, email, full_name, is_active, metadata, last_login_at, updated_at
                ) VALUES (
                    CAST(:supabase_user_id AS uuid), :email, :full_name, TRUE, CAST(:metadata AS jsonb), now(), now()
                )
                ON CONFLICT (supabase_user_id) DO UPDATE
                SET email = EXCLUDED.email,
                    full_name = EXCLUDED.full_name,
                    metadata = EXCLUDED.metadata,
                    last_login_at = now(),
                    updated_at = now()
                RETURNING id, supabase_user_id, email, full_name, metadata, is_active, (xmax = 0) AS is_new_user
                """
            ),
            {
                "supabase_user_id": supabase_user_id,
                "email": email,
                "full_name": full_name,
                "metadata": json.dumps(metadata, separators=(",", ":")),
            },
        ).mappings().one()

    if not bool(row.get("is_active", True)):
        raise APIError(code="unauthorized", message="User is disabled", status_code=401)

    row_metadata = row.get("metadata") or {}
    if isinstance(row_metadata, str):
        try:
            row_metadata = json.loads(row_metadata)
        except json.JSONDecodeError:
            row_metadata = {}

    logger.info(
        "auth_user_verified",
        extra={
            "event": "auth_user_verified",
            "user_id": str(row["id"]),
            "supabase_user_id": str(row["supabase_user_id"]),
            "email": row["email"],
        },
    )
    if bool(row.get("is_new_user")):
        try:
            notify_new_user_created(
                local_user_id=row["id"],
                supabase_user_id=row["supabase_user_id"],
                email=row["email"],
                full_name=row.get("full_name"),
            )
        except Exception:
            logger.exception(
                "admin_notify_new_user_failed",
                extra={
                    "event": "admin_notify_new_user_failed",
                    "local_user_id": str(row["id"]),
                    "supabase_user_id": str(row["supabase_user_id"]),
                    "email": row["email"],
                },
            )

    return AuthenticatedUser(
        local_user_id=row["id"],
        supabase_user_id=row["supabase_user_id"],
        email=row["email"],
        full_name=row.get("full_name"),
        metadata=row_metadata if isinstance(row_metadata, dict) else {},
        raw_supabase_user=supabase_user,
    )
