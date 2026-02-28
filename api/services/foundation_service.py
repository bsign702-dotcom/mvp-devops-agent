from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import yaml
from sqlalchemy import text
from sqlalchemy.engine import Connection

from ..db import get_engine
from ..errors import APIError

_ALLOWED_LOG_LEVELS = {"info", "warn", "error", "unknown"}
_ALLOWED_LOG_SOURCES = {"systemd", "nginx", "docker", "app", "unknown"}


def _normalize_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    value = _normalize_json(value)
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    value = _normalize_json(value)
    return value if isinstance(value, list) else []


def _validate_server_owner(conn: Connection, *, user_id: UUID, server_id: UUID) -> dict[str, Any]:
    row = conn.execute(
        text(
            """
            SELECT id, user_id, name, status, metadata, created_at, last_seen_at
            FROM servers
            WHERE id = :server_id
              AND user_id = :user_id
            """
        ),
        {"server_id": str(server_id), "user_id": str(user_id)},
    ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Server not found", status_code=404)
    return dict(row)


def _parse_service_from_message(source: str, message: str) -> str | None:
    src = (source or "").strip().lower()
    text_value = (message or "").strip()
    if not text_value:
        return None
    match = re.match(r"^\[([^\]]+)\]", text_value)
    if match:
        value = match.group(1).strip()
        if value:
            return value[:120]
    if src == "nginx":
        return "nginx"
    if src == "docker":
        return "docker"
    if src == "systemd":
        return "systemd"
    return None


def _normalize_for_fingerprint(message: str) -> str:
    value = (message or "").lower().strip()
    value = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", value)
    value = re.sub(r"\b[0-9a-f]{12,64}\b", "<hex>", value)
    value = re.sub(r"\b\d+\b", "<num>", value)
    value = re.sub(r"\s+", " ", value)
    return value[:500]


def build_log_fingerprint(source: str, service: str | None, message: str) -> str:
    normalized = _normalize_for_fingerprint(message)
    base = "|".join([(source or "unknown").lower(), (service or "").lower(), normalized])
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def list_stacks() -> list[dict[str, Any]]:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, name, description FROM stacks ORDER BY name ASC")
        ).mappings().all()
    return [dict(row) for row in rows]


def get_stack(stack_id: str) -> dict[str, Any]:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, name, description, required_inputs, steps, required_agent_capabilities
                FROM stacks
                WHERE id = :stack_id
                """
            ),
            {"stack_id": stack_id},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Stack not found", status_code=404)

    data = dict(row)
    data["required_inputs"] = [str(x) for x in _as_list(data.get("required_inputs"))]
    data["steps"] = [str(x) for x in _as_list(data.get("steps"))]
    data["required_agent_capabilities"] = [
        str(x) for x in _as_list(data.get("required_agent_capabilities"))
    ]
    return data


def _render_compose_for_stack(stack_id: str, inputs: dict[str, Any]) -> str:
    app_port = int(inputs.get("app_port") or 8000)
    image = str(inputs.get("image") or "ghcr.io/example/app:1.0.0")
    db_password = str(inputs.get("db_password") or "change_me")

    if stack_id == "python-api-postgres":
        return (
            "services:\n"
            "  app:\n"
            f"    image: {image}\n"
            "    restart: unless-stopped\n"
            "    env_file:\n"
            "      - .env\n"
            "    healthcheck:\n"
            "      test: [\"CMD\", \"curl\", \"-fsS\", \"http://localhost:8000/health\"]\n"
            "      interval: 30s\n"
            "      timeout: 5s\n"
            "      retries: 5\n"
            f"    ports:\n      - \"{app_port}:8000\"\n"
            "  db:\n"
            "    image: postgres:16\n"
            "    restart: unless-stopped\n"
            "    environment:\n"
            f"      - POSTGRES_PASSWORD={db_password}\n"
            "    healthcheck:\n"
            "      test: [\"CMD-SHELL\", \"pg_isready -U postgres\"]\n"
            "      interval: 30s\n"
            "      timeout: 5s\n"
            "      retries: 5\n"
        )

    return (
        "services:\n"
        "  app:\n"
        f"    image: {image}\n"
        "    restart: unless-stopped\n"
        "    env_file:\n"
        "      - .env\n"
        "    healthcheck:\n"
        f"      test: [\"CMD\", \"curl\", \"-fsS\", \"http://localhost:{app_port}/health\"]\n"
        "      interval: 30s\n"
        "      timeout: 5s\n"
        "      retries: 5\n"
        f"    ports:\n      - \"{app_port}:{app_port}\"\n"
    )


def _render_nginx_conf(inputs: dict[str, Any]) -> str:
    domain = str(inputs.get("domain") or "example.com").strip()
    app_port = int(inputs.get("app_port") or 8000)
    return (
        "server {\n"
        "  listen 80;\n"
        f"  server_name {domain};\n"
        "\n"
        "  location / {\n"
        f"    proxy_pass http://127.0.0.1:{app_port};\n"
        "    proxy_set_header Host $host;\n"
        "    proxy_set_header X-Real-IP $remote_addr;\n"
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "    proxy_set_header X-Forwarded-Proto $scheme;\n"
        "    proxy_set_header Upgrade $http_upgrade;\n"
        "    proxy_set_header Connection \"upgrade\";\n"
        "    proxy_connect_timeout 10s;\n"
        "    proxy_read_timeout 60s;\n"
        "    proxy_send_timeout 60s;\n"
        "  }\n"
        "}\n"
    )


def _render_env_template(inputs: dict[str, Any]) -> str:
    lines = [
        "APP_ENV=production",
        f"DOMAIN={str(inputs.get('domain') or 'example.com').strip()}",
        f"EMAIL={str(inputs.get('email') or 'admin@example.com').strip()}",
        f"APP_PORT={int(inputs.get('app_port') or 8000)}",
    ]
    if "repo_url" in inputs:
        lines.append(f"REPO_URL={str(inputs.get('repo_url') or '').strip()}")
    if "db_password" in inputs:
        lines.append(f"DB_PASSWORD={str(inputs.get('db_password') or '').strip()}")
    custom_env = inputs.get("env_vars")
    if isinstance(custom_env, dict):
        for key, value in sorted(custom_env.items()):
            key_clean = str(key).strip().upper()
            if not key_clean:
                continue
            lines.append(f"{key_clean}={str(value)}")
    return "\n".join(lines) + "\n"


def _build_provision_files(stack_id: str, server_name: str, inputs: dict[str, Any]) -> list[dict[str, str]]:
    base = f"/opt/devops/{re.sub(r'[^a-zA-Z0-9_.-]+', '-', server_name.strip().lower() or 'server')}"
    domain = str(inputs.get("domain") or "example.com").strip()
    files = [
        {"path": f"{base}/docker-compose.yml", "content": _render_compose_for_stack(stack_id, inputs)},
        {"path": f"{base}/.env", "content": _render_env_template(inputs)},
        {"path": f"/etc/nginx/sites-available/{domain}.conf", "content": _render_nginx_conf(inputs)},
    ]
    if stack_id == "python-api-postgres":
        files.append(
            {
                "path": "/etc/systemd/system/devops-app.service",
                "content": (
                    "[Unit]\nDescription=DevOps App\nAfter=docker.service\n\n"
                    "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                    f"WorkingDirectory={base}\nExecStart=/usr/bin/docker compose up -d\n"
                    "ExecStop=/usr/bin/docker compose down\n\n"
                    "[Install]\nWantedBy=multi-user.target\n"
                ),
            }
        )
    return files


def _build_provision_commands(inputs: dict[str, Any], domain: str, app_path: str) -> list[str]:
    email = str(inputs.get("email") or "admin@example.com").strip()
    return [
        "sudo apt-get update",
        "sudo apt-get install -y docker.io docker-compose-plugin nginx certbot python3-certbot-nginx ufw",
        f"cd {app_path} && sudo docker compose pull",
        f"cd {app_path} && sudo docker compose up -d",
        f"sudo ln -sf /etc/nginx/sites-available/{domain}.conf /etc/nginx/sites-enabled/{domain}.conf",
        "sudo nginx -t",
        "sudo systemctl reload nginx",
        f"sudo certbot --nginx -d {domain} -m {email} --agree-tos --no-eff-email",
        "sudo ufw allow OpenSSH",
        "sudo ufw allow 'Nginx Full'",
        "sudo ufw --force enable",
        f"curl -fsS https://{domain}/health || curl -fsS http://{domain}/health",
        "docker ps --format 'table {{.Names}}\t{{.Status}}'",
        "sudo nginx -t",
    ]


def _check_required_inputs(required_inputs: list[str], inputs: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for key in required_inputs:
        value = inputs.get(key)
        if value is None:
            missing.append(key)
            continue
        if isinstance(value, str) and not value.strip():
            missing.append(key)
    return missing


def create_provision_plan(*, user_id: UUID, server_id: UUID, stack_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    stack = get_stack(stack_id)
    missing = _check_required_inputs(stack.get("required_inputs", []), inputs)
    if missing:
        raise APIError(
            code="bad_request",
            message="Missing required inputs for selected stack",
            status_code=400,
            details={"missing_inputs": missing},
        )

    with get_engine().begin() as conn:
        server = _validate_server_owner(conn, user_id=user_id, server_id=server_id)
        files = _build_provision_files(stack_id, str(server.get("name") or "server"), inputs)
        app_path = files[0]["path"].rsplit("/", 1)[0]
        domain = str(inputs.get("domain") or "example.com").strip()
        commands = _build_provision_commands(inputs, domain, app_path)
        notes = [
            "This is a suggest-only provisioning plan. Backend does not execute remote commands.",
            "Review each file and command before applying on production.",
            "Run verification commands after each major step.",
        ]

        row = conn.execute(
            text(
                """
                INSERT INTO provision_plans (user_id, server_id, stack_id, inputs, files, commands, notes)
                VALUES (
                    :user_id, :server_id, :stack_id,
                    CAST(:inputs AS jsonb), CAST(:files AS jsonb), CAST(:commands AS jsonb), CAST(:notes AS jsonb)
                )
                RETURNING id, server_id, stack_id, files, commands, notes, created_at
                """
            ),
            {
                "user_id": str(user_id),
                "server_id": str(server_id),
                "stack_id": stack_id,
                "inputs": json.dumps(inputs, separators=(",", ":"), default=str),
                "files": json.dumps(files, separators=(",", ":"), default=str),
                "commands": json.dumps(commands, separators=(",", ":"), default=str),
                "notes": json.dumps(notes, separators=(",", ":"), default=str),
            },
        ).mappings().one()

    payload = dict(row)
    payload["plan_id"] = payload.pop("id")
    payload["files"] = _as_list(payload.get("files"))
    payload["commands"] = [str(x) for x in _as_list(payload.get("commands"))]
    payload["notes"] = [str(x) for x in _as_list(payload.get("notes"))]
    return payload


def get_provision_plan(*, user_id: UUID, plan_id: UUID) -> dict[str, Any]:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, server_id, stack_id, files, commands, notes, created_at
                FROM provision_plans
                WHERE id = :plan_id
                  AND user_id = :user_id
                """
            ),
            {"plan_id": str(plan_id), "user_id": str(user_id)},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Provision plan not found", status_code=404)

    payload = dict(row)
    payload["plan_id"] = payload.pop("id")
    payload["files"] = _as_list(payload.get("files"))
    payload["commands"] = [str(x) for x in _as_list(payload.get("commands"))]
    payload["notes"] = [str(x) for x in _as_list(payload.get("notes"))]
    return payload


def _build_preflight_checklist(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    app_port = int(inputs.get("app_port") or 8000)
    domain = str(inputs.get("domain") or "example.com").strip()
    return [
        {
            "key": "os_release",
            "title": "OS and kernel",
            "command": "uname -a && cat /etc/os-release",
            "expected": "Linux distro details are visible",
            "required": True,
        },
        {
            "key": "docker_ready",
            "title": "Docker engine available",
            "command": "docker --version && docker info --format '{{.ServerVersion}}'",
            "expected": "Docker prints a valid server version",
            "required": True,
        },
        {
            "key": "nginx_ready",
            "title": "Nginx config test",
            "command": "nginx -t",
            "expected": "test is successful",
            "required": True,
        },
        {
            "key": "port_free",
            "title": "App port availability",
            "command": f"sudo ss -lntp | grep ':{app_port} ' || true",
            "expected": "Port is free OR expected process already running",
            "required": True,
        },
        {
            "key": "dns_resolution",
            "title": "Domain resolves",
            "command": f"getent hosts {domain} || nslookup {domain}",
            "expected": "Domain resolves to server IP",
            "required": True,
        },
        {
            "key": "firewall_state",
            "title": "Firewall status",
            "command": "sudo ufw status verbose || true",
            "expected": "OpenSSH and Nginx rules can be verified",
            "required": False,
        },
    ]


def create_preflight_run(
    *,
    user_id: UUID,
    server_id: UUID,
    stack_id: str | None,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    if stack_id:
        _ = get_stack(stack_id)

    checklist = _build_preflight_checklist(inputs)
    with get_engine().begin() as conn:
        _validate_server_owner(conn, user_id=user_id, server_id=server_id)
        row = conn.execute(
            text(
                """
                INSERT INTO preflight_runs (user_id, server_id, checklist, status)
                VALUES (:user_id, :server_id, CAST(:checklist AS jsonb), 'pending')
                RETURNING id, server_id, status, checklist
                """
            ),
            {
                "user_id": str(user_id),
                "server_id": str(server_id),
                "checklist": json.dumps(checklist, separators=(",", ":")),
            },
        ).mappings().one()

    payload = dict(row)
    payload["run_id"] = payload.pop("id")
    payload["checklist"] = _as_list(payload.get("checklist"))
    return payload


def submit_preflight_results(
    *,
    user_id: UUID,
    server_id: UUID,
    run_id: UUID | None,
    results: dict[str, str],
) -> dict[str, Any]:
    with get_engine().begin() as conn:
        _validate_server_owner(conn, user_id=user_id, server_id=server_id)
        if run_id is None:
            run = conn.execute(
                text(
                    """
                    SELECT id, checklist
                    FROM preflight_runs
                    WHERE user_id = :user_id
                      AND server_id = :server_id
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"user_id": str(user_id), "server_id": str(server_id)},
            ).mappings().first()
        else:
            run = conn.execute(
                text(
                    """
                    SELECT id, checklist
                    FROM preflight_runs
                    WHERE id = :run_id
                      AND user_id = :user_id
                      AND server_id = :server_id
                    """
                ),
                {
                    "run_id": str(run_id),
                    "user_id": str(user_id),
                    "server_id": str(server_id),
                },
            ).mappings().first()
        if not run:
            raise APIError(code="not_found", message="Preflight run not found", status_code=404)

        checklist = _as_list(run.get("checklist"))
        missing: list[str] = []
        for item in checklist:
            entry = _as_dict(item)
            key = str(entry.get("key") or "").strip()
            required = bool(entry.get("required", True))
            if not key:
                continue
            value = str(results.get(key, "")).strip()
            if required and not value:
                missing.append(key)

        status = "ready" if not missing else "incomplete"
        updated = conn.execute(
            text(
                """
                UPDATE preflight_runs
                SET submitted_results = CAST(:submitted_results AS jsonb),
                    missing_items = CAST(:missing_items AS jsonb),
                    status = :status,
                    updated_at = now()
                WHERE id = :run_id
                RETURNING id, server_id, status, missing_items, submitted_results
                """
            ),
            {
                "run_id": str(run["id"]),
                "submitted_results": json.dumps(results, separators=(",", ":")),
                "missing_items": json.dumps(missing, separators=(",", ":")),
                "status": status,
            },
        ).mappings().one()

    payload = dict(updated)
    payload["run_id"] = payload.pop("id")
    payload["missing_items"] = [str(x) for x in _as_list(payload.get("missing_items"))]
    payload["submitted_results"] = {
        str(k): str(v) for k, v in _as_dict(payload.get("submitted_results")).items()
    }
    return payload


def list_templates() -> list[dict[str, Any]]:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, name, kind, description FROM templates ORDER BY name ASC")
        ).mappings().all()
    return [dict(row) for row in rows]


def get_template(template_id: str) -> dict[str, Any]:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, name, kind, description, compose, nginx_conf, env_template, metadata
                FROM templates
                WHERE id = :template_id
                """
            ),
            {"template_id": template_id},
        ).mappings().first()
    if not row:
        raise APIError(code="not_found", message="Template not found", status_code=404)
    payload = dict(row)
    payload["metadata"] = _as_dict(payload.get("metadata"))
    return payload


def lint_compose_yaml(raw_yaml: str) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        parsed = yaml.safe_load(raw_yaml) or {}
    except Exception as exc:
        return {"ok": False, "errors": [f"Invalid YAML: {exc}"], "warnings": []}

    if not isinstance(parsed, dict):
        return {"ok": False, "errors": ["Compose file root must be a mapping/object"], "warnings": []}

    services = parsed.get("services")
    if not isinstance(services, dict) or not services:
        return {"ok": False, "errors": ["`services` section is required"], "warnings": []}

    seen_ports: set[str] = set()
    seen_container_names: set[str] = set()
    for service_name, service_def in services.items():
        if not isinstance(service_def, dict):
            errors.append(f"Service `{service_name}` must be an object")
            continue

        restart = str(service_def.get("restart") or "").strip()
        if not restart:
            warnings.append(f"Service `{service_name}` has no restart policy")

        image = str(service_def.get("image") or "").strip()
        if image.endswith(":latest") or image == "latest":
            warnings.append(f"Service `{service_name}` uses latest tag")

        healthcheck = service_def.get("healthcheck")
        if any(token in str(service_name).lower() for token in ["db", "postgres", "redis", "cache"]):
            if not isinstance(healthcheck, dict):
                warnings.append(f"Service `{service_name}` should define healthcheck")

        container_name = str(service_def.get("container_name") or "").strip()
        if container_name:
            if container_name in seen_container_names:
                errors.append(f"Duplicate container_name `{container_name}`")
            seen_container_names.add(container_name)

        for port in _as_list(service_def.get("ports")):
            if isinstance(port, int):
                host_port = str(port)
            else:
                value = str(port)
                if ":" not in value:
                    continue
                host_port = value.split(":", 1)[0].strip().strip('"').strip("'")
            if not host_port:
                continue
            if host_port in seen_ports:
                errors.append(f"Host port conflict detected: {host_port}")
            seen_ports.add(host_port)

    return {"ok": len(errors) == 0, "errors": errors, "warnings": warnings}


def lint_nginx_conf(conf: str) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    normalized = conf or ""
    lower = normalized.lower()

    if "server_name" not in lower:
        errors.append("Missing `server_name` directive")

    if "proxy_pass" in lower:
        required_headers = [
            "proxy_set_header host",
            "proxy_set_header upgrade",
            "proxy_set_header connection",
        ]
        for hdr in required_headers:
            if hdr not in lower:
                warnings.append(f"Missing proxy header: `{hdr}`")

        timeout_keys = ["proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout"]
        for timeout_key in timeout_keys:
            if timeout_key not in lower:
                warnings.append(f"Missing upstream timeout: `{timeout_key}`")

    if "rewrite" in lower and "return 301" not in lower and "return 302" not in lower:
        warnings.append("Rewrite directive detected; verify rewrite rules are intentional")

    return {"ok": len(errors) == 0, "errors": errors, "warnings": warnings}


def _coerce_dt(value: datetime | None, fallback: datetime) -> datetime:
    if value is None:
        return fallback
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def search_server_logs(
    *,
    user_id: UUID,
    server_id: UUID,
    source: str | None,
    level: str | None,
    query: str | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since_dt = _coerce_dt(since, now - timedelta(hours=24))
    until_dt = _coerce_dt(until, now)

    conditions = ["server_id = :server_id", "ts >= :since", "ts <= :until"]
    params: dict[str, Any] = {
        "server_id": str(server_id),
        "since": since_dt,
        "until": until_dt,
        "limit": limit,
    }

    if source:
        conditions.append("source = :source")
        params["source"] = source
    if level:
        conditions.append("level = :level")
        params["level"] = level
    if query:
        conditions.append("message ILIKE :q")
        params["q"] = f"%{query}%"

    where_clause = " AND ".join(conditions)

    with get_engine().connect() as conn:
        _validate_server_owner(conn, user_id=user_id, server_id=server_id)

        rows = conn.execute(
            text(
                f"""
                SELECT id, ts, source, service, level, message, fingerprint, tags
                FROM server_logs
                WHERE {where_clause}
                ORDER BY ts DESC
                LIMIT :limit
                """
            ),
            params,
        ).mappings().all()

        by_fingerprint_rows = conn.execute(
            text(
                f"""
                SELECT fingerprint, COUNT(*) AS count, MIN(message) AS sample_message
                FROM server_logs
                WHERE {where_clause}
                GROUP BY fingerprint
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """
            ),
            {k: v for k, v in params.items() if k != "limit"},
        ).mappings().all()

        top_source_rows = conn.execute(
            text(
                f"""
                SELECT source AS name, COUNT(*) AS count
                FROM server_logs
                WHERE {where_clause}
                GROUP BY source
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """
            ),
            {k: v for k, v in params.items() if k != "limit"},
        ).mappings().all()

        top_service_rows = conn.execute(
            text(
                f"""
                SELECT COALESCE(service, 'unknown') AS name, COUNT(*) AS count
                FROM server_logs
                WHERE {where_clause}
                GROUP BY COALESCE(service, 'unknown')
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """
            ),
            {k: v for k, v in params.items() if k != "limit"},
        ).mappings().all()

    items = []
    for row in rows:
        item = dict(row)
        item["source"] = item["source"] if item["source"] in _ALLOWED_LOG_SOURCES else "unknown"
        item["level"] = item["level"] if item["level"] in _ALLOWED_LOG_LEVELS else "unknown"
        item["tags"] = [str(x) for x in _as_list(item.get("tags"))]
        items.append(item)

    return {
        "items": items,
        "by_fingerprint": [dict(row) for row in by_fingerprint_rows],
        "top_sources": [dict(row) for row in top_source_rows],
        "top_services": [dict(row) for row in top_service_rows],
    }


def get_metrics_history(
    *,
    user_id: UUID,
    server_id: UUID,
    since: datetime | None,
    until: datetime | None,
    bucket: str,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since_dt = _coerce_dt(since, now - timedelta(hours=24))
    until_dt = _coerce_dt(until, now)

    if bucket not in {"1m", "5m", "1h"}:
        raise APIError(code="bad_request", message="bucket must be one of 1m|5m|1h", status_code=400)

    bucket_expr_map = {
        "1m": "date_trunc('minute', ts)",
        "5m": "to_timestamp(floor(extract(epoch from ts)/300)*300)",
        "1h": "date_trunc('hour', ts)",
    }
    bucket_expr = bucket_expr_map[bucket]

    with get_engine().connect() as conn:
        _validate_server_owner(conn, user_id=user_id, server_id=server_id)
        rows = conn.execute(
            text(
                f"""
                SELECT
                    {bucket_expr} AS bucket_ts,
                    AVG(cpu_percent) AS cpu_avg,
                    AVG(ram_percent) AS ram_avg,
                    AVG(disk_percent) AS disk_avg,
                    AVG(load1) AS load1_avg,
                    MAX(net_bytes_sent) AS net_sent_max,
                    MAX(net_bytes_recv) AS net_recv_max,
                    COUNT(*)::int AS sample_count
                FROM server_metrics
                WHERE server_id = :server_id
                  AND ts >= :since
                  AND ts <= :until
                GROUP BY 1
                ORDER BY 1 ASC
                """
            ),
            {"server_id": str(server_id), "since": since_dt, "until": until_dt},
        ).mappings().all()

    return {
        "server_id": server_id,
        "bucket": bucket,
        "points": [dict(row) for row in rows],
    }


def get_timeline(
    *,
    user_id: UUID,
    server_id: UUID,
    since: datetime | None,
    until: datetime | None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since_dt = _coerce_dt(since, now - timedelta(hours=24))
    until_dt = _coerce_dt(until, now)

    with get_engine().connect() as conn:
        _validate_server_owner(conn, user_id=user_id, server_id=server_id)

        alert_rows = conn.execute(
            text(
                """
                SELECT ts, type, severity, title, details
                FROM alerts
                WHERE server_id = :server_id
                  AND ts >= :since
                  AND ts <= :until
                ORDER BY ts DESC
                LIMIT 300
                """
            ),
            {"server_id": str(server_id), "since": since_dt, "until": until_dt},
        ).mappings().all()

        event_rows = conn.execute(
            text(
                """
                SELECT ts, event_type, source, title, payload
                FROM server_events
                WHERE server_id = :server_id
                  AND ts >= :since
                  AND ts <= :until
                ORDER BY ts DESC
                LIMIT 300
                """
            ),
            {"server_id": str(server_id), "since": since_dt, "until": until_dt},
        ).mappings().all()

        log_rows = conn.execute(
            text(
                """
                SELECT ts, source, level, message, service, fingerprint
                FROM server_logs
                WHERE server_id = :server_id
                  AND ts >= :since
                  AND ts <= :until
                  AND level IN ('warn', 'error')
                ORDER BY ts DESC
                LIMIT 300
                """
            ),
            {"server_id": str(server_id), "since": since_dt, "until": until_dt},
        ).mappings().all()

    timeline_items: list[dict[str, Any]] = []
    for row in alert_rows:
        item = dict(row)
        timeline_items.append(
            {
                "ts": item["ts"],
                "category": "alert",
                "source": "alerts",
                "title": item.get("title") or item.get("type") or "alert",
                "severity": item.get("severity"),
                "payload": {
                    "type": item.get("type"),
                    "details": _as_dict(item.get("details")),
                },
            }
        )

    for row in event_rows:
        item = dict(row)
        timeline_items.append(
            {
                "ts": item["ts"],
                "category": "event",
                "source": str(item.get("source") or "unknown"),
                "title": item.get("title") or item.get("event_type") or "event",
                "severity": None,
                "payload": {
                    "event_type": item.get("event_type"),
                    "payload": _as_dict(item.get("payload")),
                },
            }
        )

    for row in log_rows:
        item = dict(row)
        timeline_items.append(
            {
                "ts": item["ts"],
                "category": "log",
                "source": str(item.get("source") or "unknown"),
                "title": str(item.get("message") or "log")[:180],
                "severity": item.get("level"),
                "payload": {
                    "service": item.get("service"),
                    "fingerprint": item.get("fingerprint"),
                },
            }
        )

    timeline_items.sort(key=lambda row: row.get("ts") or now, reverse=True)
    return {"server_id": server_id, "items": timeline_items[:500]}


def build_troubleshooting_packet(*, user_id: UUID, server_id: UUID) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)

    with get_engine().connect() as conn:
        server = _validate_server_owner(conn, user_id=user_id, server_id=server_id)
        metadata = _as_dict(server.get("metadata"))
        host = _as_dict(metadata.get("host"))

        latest_metric = conn.execute(
            text(
                """
                SELECT ts, cpu_percent, ram_percent, disk_percent, load1, load5, load15,
                       net_bytes_sent, net_bytes_recv
                FROM server_metrics
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 1
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

        trend_row = conn.execute(
            text(
                """
                SELECT
                    AVG(cpu_percent) AS cpu_avg_1h,
                    AVG(ram_percent) AS ram_avg_1h,
                    AVG(disk_percent) AS disk_avg_1h,
                    COUNT(*)::int AS sample_count_1h
                FROM server_metrics
                WHERE server_id = :server_id
                  AND ts >= now() - interval '1 hour'
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

        recent_alerts = conn.execute(
            text(
                """
                SELECT id, ts, type, severity, title, details, is_resolved
                FROM alerts
                WHERE server_id = :server_id
                ORDER BY ts DESC
                LIMIT 30
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        logs_rows = conn.execute(
            text(
                """
                SELECT id, ts, source, service, level, message, fingerprint
                FROM server_logs
                WHERE server_id = :server_id
                  AND ts >= :since
                  AND level IN ('warn', 'error')
                ORDER BY ts DESC
                LIMIT 120
                """
            ),
            {"server_id": str(server_id), "since": since_24h},
        ).mappings().all()

        docker_event_rows = conn.execute(
            text(
                """
                SELECT ts, event_type, source, service, title, payload
                FROM server_events
                WHERE server_id = :server_id
                  AND source = 'docker'
                ORDER BY ts DESC
                LIMIT 80
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().all()

        plan_rows = conn.execute(
            text(
                """
                SELECT id, stack_id, created_at, notes
                FROM provision_plans
                WHERE user_id = :user_id
                  AND server_id = :server_id
                ORDER BY created_at DESC
                LIMIT 5
                """
            ),
            {"user_id": str(user_id), "server_id": str(server_id)},
        ).mappings().all()

        cap_row = conn.execute(
            text(
                """
                SELECT supports_docker, supports_systemd, supports_journalctl, supports_nginx_logs,
                       nginx_paths, docker_version, systemd_version, metadata, updated_at
                FROM agent_capabilities
                WHERE server_id = :server_id
                """
            ),
            {"server_id": str(server_id)},
        ).mappings().first()

    by_source: dict[str, list[dict[str, Any]]] = {"systemd": [], "nginx": [], "docker": [], "app": []}
    for row in logs_rows:
        item = dict(row)
        src = str(item.get("source") or "unknown")
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(item)

    return {
        "server": {
            "id": str(server["id"]),
            "name": server.get("name"),
            "status": server.get("status"),
            "created_at": server.get("created_at"),
            "last_seen_at": server.get("last_seen_at"),
        },
        "identity": {
            "primary_ip": host.get("primary_ip"),
            "ip_addresses": [str(x) for x in _as_list(host.get("ip_addresses"))],
            "domains": [str(x) for x in _as_list(host.get("domains"))],
            "agent_client_ip": host.get("agent_client_ip"),
        },
        "metrics_snapshot": dict(latest_metric) if latest_metric else {},
        "metric_trend": dict(trend_row) if trend_row else {},
        "recent_alerts": [
            {**dict(row), "details": _as_dict(row.get("details"))}
            for row in recent_alerts
        ],
        "recent_logs": by_source,
        "recent_docker_events": [
            {**dict(row), "payload": _as_dict(row.get("payload"))}
            for row in docker_event_rows
        ],
        "recent_provision_plans": [
            {
                "id": str(row["id"]),
                "stack_id": row.get("stack_id"),
                "created_at": row.get("created_at"),
                "notes": [str(x) for x in _as_list(row.get("notes"))],
            }
            for row in plan_rows
        ],
        "agent_capabilities": {
            **(dict(cap_row) if cap_row else {}),
            "nginx_paths": [str(x) for x in _as_list(cap_row.get("nginx_paths"))] if cap_row else [],
            "metadata": _as_dict(cap_row.get("metadata")) if cap_row else {},
        },
    }


def build_chat_context_packet(*, user_id: UUID, server_id: UUID) -> dict[str, Any]:
    packet = build_troubleshooting_packet(user_id=user_id, server_id=server_id)
    return {
        "server": packet.get("server", {}),
        "identity": packet.get("identity", {}),
        "metrics_snapshot": packet.get("metrics_snapshot", {}),
        "metric_trend": packet.get("metric_trend", {}),
        "alerts": packet.get("recent_alerts", [])[:20],
        "logs": packet.get("recent_logs", {}),
        "docker_events": packet.get("recent_docker_events", [])[:40],
        "recent_provision_plans": packet.get("recent_provision_plans", []),
        "agent_capabilities": packet.get("agent_capabilities", {}),
    }


def upsert_agent_self_check(*, token_hash: str, payload: dict[str, Any]) -> dict[str, Any]:
    with get_engine().begin() as conn:
        server = conn.execute(
            text(
                """
                SELECT id, metadata
                FROM servers
                WHERE agent_token_hash = :token_hash
                LIMIT 1
                """
            ),
            {"token_hash": token_hash},
        ).mappings().first()
        if not server:
            raise APIError(code="unauthorized", message="Invalid agent token", status_code=401)

        server_id = server["id"]
        metadata = _as_dict(server.get("metadata"))

        tags = payload.get("tags") if isinstance(payload.get("tags"), dict) else {}
        metadata_patch = {
            "agent_tags": {str(k): str(v) for k, v in tags.items()},
            "agent_last_self_check_ts": datetime.now(timezone.utc).isoformat(),
        }

        cap_data = {
            "supports_docker": bool(payload.get("supports_docker", False)),
            "supports_systemd": bool(payload.get("systemd_available", False)) or bool(payload.get("supports_systemd_logs", False)),
            "supports_journalctl": bool(payload.get("journalctl_access", False)) or bool(payload.get("supports_journalctl_logs", False)),
            "supports_nginx_logs": bool(payload.get("supports_nginx_logs", False)),
            "nginx_paths": [str(x) for x in _as_list(payload.get("nginx_paths"))][:30],
            "docker_version": str(payload.get("docker_version") or "").strip() or None,
            "systemd_version": str(payload.get("systemd_version") or "").strip() or None,
            "metadata": payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        }

        conn.execute(
            text(
                """
                INSERT INTO agent_capabilities (
                    server_id, supports_docker, supports_systemd, supports_journalctl,
                    supports_nginx_logs, nginx_paths, docker_version, systemd_version, metadata, created_at, updated_at
                )
                VALUES (
                    :server_id, :supports_docker, :supports_systemd, :supports_journalctl,
                    :supports_nginx_logs, CAST(:nginx_paths AS jsonb), :docker_version, :systemd_version,
                    CAST(:metadata AS jsonb), now(), now()
                )
                ON CONFLICT (server_id) DO UPDATE
                SET supports_docker = EXCLUDED.supports_docker,
                    supports_systemd = EXCLUDED.supports_systemd,
                    supports_journalctl = EXCLUDED.supports_journalctl,
                    supports_nginx_logs = EXCLUDED.supports_nginx_logs,
                    nginx_paths = EXCLUDED.nginx_paths,
                    docker_version = EXCLUDED.docker_version,
                    systemd_version = EXCLUDED.systemd_version,
                    metadata = EXCLUDED.metadata,
                    updated_at = now()
                """
            ),
            {
                "server_id": str(server_id),
                "supports_docker": cap_data["supports_docker"],
                "supports_systemd": cap_data["supports_systemd"],
                "supports_journalctl": cap_data["supports_journalctl"],
                "supports_nginx_logs": cap_data["supports_nginx_logs"],
                "nginx_paths": json.dumps(cap_data["nginx_paths"], separators=(",", ":")),
                "docker_version": cap_data["docker_version"],
                "systemd_version": cap_data["systemd_version"],
                "metadata": json.dumps(cap_data["metadata"], separators=(",", ":")),
            },
        )

        conn.execute(
            text(
                """
                INSERT INTO server_heartbeats (server_id, ts, source, metadata)
                VALUES (:server_id, now(), 'self_check', CAST(:metadata AS jsonb))
                """
            ),
            {
                "server_id": str(server_id),
                "metadata": json.dumps({"self_check": True}, separators=(",", ":")),
            },
        )

        conn.execute(
            text(
                """
                UPDATE servers
                SET metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:metadata_patch AS jsonb),
                    last_seen_at = now(),
                    status = 'connected'
                WHERE id = :server_id
                """
            ),
            {
                "server_id": str(server_id),
                "metadata_patch": json.dumps(metadata_patch, separators=(",", ":")),
            },
        )

    return {
        "server_id": server_id,
        "capabilities": {
            **cap_data,
            "nginx_paths": cap_data["nginx_paths"],
        },
    }


def get_agent_install_config(*, token_hash: str, default_image: str) -> dict[str, Any]:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, metadata
                FROM servers
                WHERE agent_token_hash = :token_hash
                LIMIT 1
                """
            ),
            {"token_hash": token_hash},
        ).mappings().first()
    if not row:
        raise APIError(code="unauthorized", message="Invalid agent token", status_code=401)

    metadata = _as_dict(row.get("metadata"))
    agent_image = str(metadata.get("agent_image") or "").strip() or default_image
    return {
        "server_id": str(row["id"]),
        "agent_image": agent_image,
    }
