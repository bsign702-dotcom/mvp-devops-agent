from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, RowMapping

from .settings import get_settings

logger = logging.getLogger(__name__)

_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    return _engine


def fetch_all(query: str, params: dict[str, Any] | None = None) -> list[RowMapping]:
    with get_engine().connect() as conn:
        result = conn.execute(text(query), params or {})
        return list(result.mappings())


def fetch_one(query: str, params: dict[str, Any] | None = None) -> RowMapping | None:
    with get_engine().connect() as conn:
        result = conn.execute(text(query), params or {})
        row = result.mappings().first()
        return row


def execute(query: str, params: dict[str, Any] | None = None) -> None:
    with get_engine().begin() as conn:
        conn.execute(text(query), params or {})


def _migrations_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "migrations"


def _migration_paths() -> list[Path]:
    return sorted(_migrations_dir().glob("*.sql"))


def _split_sql_statements(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        current.append(line)
        if stripped.endswith(";"):
            statement = "\n".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
    tail = "\n".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def ensure_migrated() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_lock(88223311)"))
        try:
            conn.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version text PRIMARY KEY,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
            applied = {
                row[0]
                for row in conn.exec_driver_sql("SELECT version FROM schema_migrations").fetchall()
            }
            applied_now: list[str] = []
            for path in _migration_paths():
                version = path.name
                if version in applied:
                    continue
                sql = path.read_text(encoding="utf-8")
                for statement in _split_sql_statements(sql):
                    conn.exec_driver_sql(statement)
                conn.execute(
                    text("INSERT INTO schema_migrations (version) VALUES (:version)"),
                    {"version": version},
                )
                applied_now.append(version)
            if applied_now:
                logger.info(
                    "migrations_applied",
                    extra={"event": "migrations_applied", "versions": applied_now},
                )
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(88223311)"))


def wait_for_db(max_attempts: int = 20, sleep_seconds: float = 2.0) -> None:
    engine = get_engine()
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # pragma: no cover - best effort startup retry
            last_error = exc
            logger.warning(
                "db_wait_retry",
                extra={"event": "db_wait_retry", "attempt": attempt, "max_attempts": max_attempts},
            )
            time.sleep(sleep_seconds)
    if last_error:
        raise last_error
