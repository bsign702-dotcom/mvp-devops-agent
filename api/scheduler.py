from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import text

from .alerts import create_alert_if_needed, resolve_alert_type
from .db import get_engine
from .settings import get_settings
from .services.notification_service import run_daily_reports_cycle
from .services.uptime_service import UPTIME_SCHEDULER_INTERVAL_SECONDS, run_uptime_checks_cycle

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def _offline_check_job() -> None:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=settings.offline_after_seconds)

    with get_engine().begin() as conn:
        offline_rows = conn.execute(
            text(
                """
                SELECT s.id, s.name, COALESCE(h.last_heartbeat_at, s.last_seen_at) AS last_seen_at
                FROM servers s
                LEFT JOIN (
                    SELECT server_id, MAX(ts) AS last_heartbeat_at
                    FROM server_heartbeats
                    GROUP BY server_id
                ) h ON h.server_id = s.id
                WHERE COALESCE(h.last_heartbeat_at, s.last_seen_at) IS NULL
                   OR COALESCE(h.last_heartbeat_at, s.last_seen_at) < :cutoff
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()

        for row in offline_rows:
            conn.execute(
                text("UPDATE servers SET status = 'offline' WHERE id = :id AND status <> 'offline'"),
                {"id": row["id"]},
            )
            create_alert_if_needed(
                conn,
                server_id=row["id"],
                alert_type="agent_offline",
                severity="critical",
                title="Agent is offline",
                details={
                    "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
                    "offline_after_seconds": settings.offline_after_seconds,
                },
                dedupe_seconds=settings.alert_dedupe_seconds,
                now=now,
            )

        recent_rows = conn.execute(
            text(
                """
                SELECT s.id
                FROM servers s
                LEFT JOIN (
                    SELECT server_id, MAX(ts) AS last_heartbeat_at
                    FROM server_heartbeats
                    GROUP BY server_id
                ) h ON h.server_id = s.id
                WHERE COALESCE(h.last_heartbeat_at, s.last_seen_at) IS NOT NULL
                  AND COALESCE(h.last_heartbeat_at, s.last_seen_at) >= :cutoff
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()
        for row in recent_rows:
            conn.execute(
                text("UPDATE servers SET status = 'connected' WHERE id = :id AND status = 'offline'"),
                {"id": row["id"]},
            )
            resolve_alert_type(conn, row["id"], "agent_offline")

    logger.info(
        "offline_check_completed",
        extra={
            "event": "offline_check_completed",
            "offline_candidates": len(offline_rows),
            "recent_candidates": len(recent_rows),
        },
    )


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    settings = get_settings()
    scheduler = AsyncIOScheduler(event_loop=asyncio.get_running_loop(), timezone="UTC")
    scheduler.add_job(
        _offline_check_job,
        "interval",
        seconds=settings.offline_check_interval_seconds,
        id="offline-check",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        run_uptime_checks_cycle,
        "interval",
        seconds=UPTIME_SCHEDULER_INTERVAL_SECONDS,
        id="uptime-checks",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        run_daily_reports_cycle,
        "interval",
        minutes=1,
        id="daily-reports",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    _scheduler = scheduler
    logger.info("scheduler_started", extra={"event": "scheduler_started"})


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is None:
        return
    _scheduler.shutdown(wait=False)
    _scheduler = None
    logger.info("scheduler_stopped", extra={"event": "scheduler_stopped"})
