from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import text

from ..alerts import create_alert_if_needed, resolve_alert_type
from ..db import get_engine
from ..settings import get_settings

logger = logging.getLogger(__name__)

UPTIME_SCHEDULER_INTERVAL_SECONDS = 15
MAX_CONCURRENT_UPTIME_CHECKS = 20
SSL_EXPIRY_ALERT_DAYS = 7


@dataclass(slots=True)
class MonitorCheckOutcome:
    monitor_id: UUID
    checked_at: datetime
    status: str
    response_time_ms: int | None
    status_code: int | None
    error_message: str | None
    ssl_expires_at: datetime | None


def _fetch_due_monitors() -> list[dict[str, Any]]:
    query = text(
        """
        SELECT id, name, url, check_interval_sec, timeout_sec, expected_status,
               last_status, last_response_time_ms, last_checked_at, consecutive_failures, created_at
        FROM uptime_monitors
        WHERE last_checked_at IS NULL
           OR last_checked_at <= now() - make_interval(secs => check_interval_sec)
        ORDER BY COALESCE(last_checked_at, to_timestamp(0)) ASC
        LIMIT 500
        """
    )
    with get_engine().connect() as conn:
        return [dict(row) for row in conn.execute(query).mappings().all()]


async def _read_ssl_expiry(url: str, timeout_sec: int) -> datetime | None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None

    host = parsed.hostname
    port = parsed.port or 443
    ssl_ctx = ssl.create_default_context()

    try:
        connect_coro = asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=host)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout_sec)
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return None
            cert = ssl_object.getpeercert()
            not_after = cert.get("notAfter")
            if not not_after:
                return None
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return expires_at.replace(tzinfo=timezone.utc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (asyncio.TimeoutError, ssl.SSLError, OSError, socket.gaierror):
        return None


async def _check_monitor(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    monitor: dict[str, Any],
) -> MonitorCheckOutcome:
    async with semaphore:
        checked_at = datetime.now(timezone.utc)
        response_time_ms: int | None = None
        status_code: int | None = None
        error_message: str | None = None
        status = "down"
        ssl_expires_at: datetime | None = None
        timeout_sec = int(monitor["timeout_sec"])

        start = time.perf_counter()
        try:
            response = await client.get(monitor["url"], timeout=httpx.Timeout(timeout_sec))
            response_time_ms = int((time.perf_counter() - start) * 1000)
            status_code = response.status_code
            if response.status_code == int(monitor["expected_status"]):
                status = "up"
            else:
                error_message = f"Unexpected status code {response.status_code} (expected {monitor['expected_status']})"
        except (httpx.TimeoutException, asyncio.TimeoutError):
            response_time_ms = int((time.perf_counter() - start) * 1000)
            error_message = f"Request timed out after {timeout_sec}s"
        except httpx.HTTPError as exc:
            response_time_ms = int((time.perf_counter() - start) * 1000)
            error_message = str(exc)

        if status == "up":
            ssl_expires_at = await _read_ssl_expiry(monitor["url"], timeout_sec)

        return MonitorCheckOutcome(
            monitor_id=monitor["id"],
            checked_at=checked_at,
            status=status,
            response_time_ms=response_time_ms,
            status_code=status_code,
            error_message=error_message,
            ssl_expires_at=ssl_expires_at,
        )


def _persist_outcome(monitor: dict[str, Any], outcome: MonitorCheckOutcome) -> dict[str, Any]:
    settings = get_settings()
    slow_threshold_ms = max(1, int(settings.uptime_slow_threshold_ms))
    previous_failures = int(monitor.get("consecutive_failures") or 0)
    previous_status = str(monitor.get("last_status") or "unknown")
    new_failures = previous_failures + 1 if outcome.status == "down" else 0
    alerts_created: list[str] = []

    with get_engine().begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO uptime_checks (
                    monitor_id, status, response_time_ms, status_code, error_message, checked_at
                ) VALUES (
                    :monitor_id, :status, :response_time_ms, :status_code, :error_message, :checked_at
                )
                """
            ),
            {
                "monitor_id": str(outcome.monitor_id),
                "status": outcome.status,
                "response_time_ms": outcome.response_time_ms,
                "status_code": outcome.status_code,
                "error_message": outcome.error_message,
                "checked_at": outcome.checked_at,
            },
        )

        conn.execute(
            text(
                """
                UPDATE uptime_monitors
                SET last_status = :last_status,
                    last_response_time_ms = :last_response_time_ms,
                    last_checked_at = :last_checked_at,
                    consecutive_failures = :consecutive_failures
                WHERE id = :monitor_id
                """
            ),
            {
                "monitor_id": str(outcome.monitor_id),
                "last_status": outcome.status,
                "last_response_time_ms": outcome.response_time_ms,
                "last_checked_at": outcome.checked_at,
                "consecutive_failures": new_failures,
            },
        )

        if outcome.status == "down":
            # Down supersedes slow; close any outstanding slow alert while monitor is down.
            resolve_alert_type(conn, None, "UPTIME_SLOW", uptime_monitor_id=outcome.monitor_id)
            if new_failures >= 3:
                if create_alert_if_needed(
                    conn,
                    uptime_monitor_id=outcome.monitor_id,
                    alert_type="UPTIME_DOWN",
                    severity="critical",
                    title=f"Uptime monitor down: {monitor['name']}",
                    details={
                        "url": monitor["url"],
                        "status_code": outcome.status_code,
                        "error_message": outcome.error_message,
                        "consecutive_failures": new_failures,
                        "expected_status": int(monitor["expected_status"]),
                        "response_time_ms": outcome.response_time_ms,
                    },
                    dedupe_seconds=settings.alert_dedupe_seconds,
                ):
                    alerts_created.append("UPTIME_DOWN")
        else:
            if previous_failures >= 3 or previous_status == "down":
                resolve_alert_type(conn, None, "UPTIME_DOWN", uptime_monitor_id=outcome.monitor_id)
                if create_alert_if_needed(
                    conn,
                    uptime_monitor_id=outcome.monitor_id,
                    alert_type="UPTIME_RECOVERED",
                    severity="medium",
                    title=f"Uptime monitor recovered: {monitor['name']}",
                    details={
                        "url": monitor["url"],
                        "status_code": outcome.status_code,
                        "response_time_ms": outcome.response_time_ms,
                        "previous_consecutive_failures": previous_failures,
                    },
                    dedupe_seconds=settings.alert_dedupe_seconds,
                ):
                    alerts_created.append("UPTIME_RECOVERED")
                    # Recovery is an event-type alert; resolve it immediately so future recoveries can be emitted.
                    resolve_alert_type(conn, None, "UPTIME_RECOVERED", uptime_monitor_id=outcome.monitor_id)

            if outcome.response_time_ms is not None and outcome.response_time_ms >= slow_threshold_ms:
                if create_alert_if_needed(
                    conn,
                    uptime_monitor_id=outcome.monitor_id,
                    alert_type="UPTIME_SLOW",
                    severity="high",
                    title=f"Uptime monitor is slow: {monitor['name']}",
                    details={
                        "url": monitor["url"],
                        "response_time_ms": outcome.response_time_ms,
                        "threshold_ms": slow_threshold_ms,
                        "status_code": outcome.status_code,
                    },
                    dedupe_seconds=settings.alert_dedupe_seconds,
                ):
                    alerts_created.append("UPTIME_SLOW")
            else:
                resolve_alert_type(conn, None, "UPTIME_SLOW", uptime_monitor_id=outcome.monitor_id)

            if outcome.ssl_expires_at is not None:
                now = datetime.now(timezone.utc)
                days_remaining = (outcome.ssl_expires_at - now).total_seconds() / 86400
                if days_remaining < SSL_EXPIRY_ALERT_DAYS:
                    if create_alert_if_needed(
                        conn,
                        uptime_monitor_id=outcome.monitor_id,
                        alert_type="SSL_EXPIRING",
                        severity="high" if days_remaining < 3 else "medium",
                        title=f"SSL certificate expiring soon: {monitor['name']}",
                        details={
                            "url": monitor["url"],
                            "expires_at": outcome.ssl_expires_at.isoformat(),
                            "days_remaining": round(days_remaining, 2),
                            "threshold_days": SSL_EXPIRY_ALERT_DAYS,
                        },
                        dedupe_seconds=settings.alert_dedupe_seconds,
                    ):
                        alerts_created.append("SSL_EXPIRING")
                else:
                    resolve_alert_type(conn, None, "SSL_EXPIRING", uptime_monitor_id=outcome.monitor_id)

    return {
        "monitor_id": str(outcome.monitor_id),
        "status": outcome.status,
        "status_code": outcome.status_code,
        "response_time_ms": outcome.response_time_ms,
        "alerts_created": alerts_created,
    }


async def run_uptime_checks_cycle() -> None:
    monitors = await asyncio.to_thread(_fetch_due_monitors)
    if not monitors:
        return

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_UPTIME_CHECKS)
    timeout_cap = max(int(m.get("timeout_sec") or 10) for m in monitors)
    client_timeout = httpx.Timeout(timeout=max(5, timeout_cap + 1))

    async with httpx.AsyncClient(follow_redirects=True, timeout=client_timeout) as client:
        outcomes = await asyncio.gather(
            *[_check_monitor(client, semaphore, monitor) for monitor in monitors],
            return_exceptions=True,
        )

    persisted = 0
    for monitor, outcome in zip(monitors, outcomes):
        if isinstance(outcome, Exception):
            logger.error(
                "uptime_check_execution_error",
                extra={
                    "event": "uptime_check_execution_error",
                    "monitor_id": str(monitor["id"]),
                    "error_type": outcome.__class__.__name__,
                    "error": str(outcome),
                },
            )
            fallback = MonitorCheckOutcome(
                monitor_id=monitor["id"],
                checked_at=datetime.now(timezone.utc),
                status="down",
                response_time_ms=None,
                status_code=None,
                error_message=f"internal_error: {outcome.__class__.__name__}",
                ssl_expires_at=None,
            )
            await asyncio.to_thread(_persist_outcome, monitor, fallback)
            persisted += 1
            continue
        await asyncio.to_thread(_persist_outcome, monitor, outcome)
        persisted += 1

    logger.info(
        "uptime_checks_cycle_completed",
        extra={
            "event": "uptime_checks_cycle_completed",
            "due_monitors": len(monitors),
            "persisted": persisted,
        },
    )
