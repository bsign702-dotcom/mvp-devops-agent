from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

import psutil
import requests

_file_offsets: dict[str, int] = {}


def log(event: str, **kwargs: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **kwargs,
    }
    print(json.dumps(payload, default=str, separators=(",", ":")), flush=True)


def env_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def collect_host() -> dict[str, Any]:
    ip_addresses = _collect_ip_addresses()
    domains = _collect_domains_from_nginx_config()
    primary_ip = ip_addresses[0] if ip_addresses else None
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "primary_ip": primary_ip,
        "ip_addresses": ip_addresses,
        "domains": domains,
    }


def _parse_agent_tags() -> dict[str, str]:
    raw = os.getenv("AGENT_TAGS", "").strip()
    if not raw:
        return {}
    pairs = [x.strip() for x in raw.split(",") if x.strip()]
    tags: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        tags[key[:64]] = value[:256]
    return tags


def _collect_ip_addresses() -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = str(addr.address).strip()
                if not ip or ip.startswith("127.") or ip in seen:
                    continue
                seen.add(ip)
                ips.append(ip)
    except Exception as exc:
        log("host_ip_collect_failed", error=str(exc))
    return sorted(ips)


def _collect_domains_from_nginx_config() -> list[str]:
    roots = [
        "/host_etc_nginx",
        "/etc/nginx",
    ]
    names: set[str] = set()
    pattern = re.compile(r"\bserver_name\s+([^;]+);")
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            if len(names) >= 30:
                break
            for filename in sorted(filenames):
                path = os.path.join(dirpath, filename)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            match = pattern.search(line)
                            if not match:
                                continue
                            for token in match.group(1).split():
                                domain = token.strip().lower()
                                if not domain or domain in {"_", "localhost"}:
                                    continue
                                names.add(domain)
                except Exception:
                    continue
    return sorted(names)[:30]


def collect_metrics() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    try:
        loadavg = list(os.getloadavg())
    except (AttributeError, OSError):
        loadavg = [0.0, 0.0, 0.0]

    return {
        "cpu_percent": float(psutil.cpu_percent(interval=None)),
        "ram_percent": float(vm.percent),
        "disk_percent": float(disk.percent),
        "loadavg": [float(x) for x in loadavg],
        "net_bytes_sent": int(getattr(net, "bytes_sent", 0)),
        "net_bytes_recv": int(getattr(net, "bytes_recv", 0)),
    }


def _run_command(cmd: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str] | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        log("command_failed", command=cmd, error=str(exc))
        return None


def collect_docker(interval_sec: int) -> dict[str, Any]:
    result: dict[str, Any] = {"containers": [], "events": []}
    ps_proc = _run_command(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=5)
    if ps_proc and ps_proc.returncode == 0:
        for line in ps_proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            result["containers"].append(
                {
                    "id": row.get("ID", ""),
                    "image": row.get("Image", ""),
                    "name": row.get("Names", ""),
                    "status": row.get("Status", ""),
                }
            )

    end_ts = int(time.time())
    start_ts = max(0, end_ts - int(interval_sec))
    events_proc = _run_command(
        [
            "docker",
            "events",
            "--since",
            str(start_ts),
            "--until",
            str(end_ts),
            "--format",
            "{{json .}}",
        ],
        timeout=5,
    )
    if events_proc and events_proc.returncode == 0:
        for line in events_proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result["events"].append(json.loads(line))
            except json.JSONDecodeError:
                result["events"].append({"raw": line})
    return result


def _read_new_file_lines(path: str, *, max_bytes: int, max_lines: int) -> list[str]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as f:
            file_size = f.seek(0, os.SEEK_END)
            last_offset = _file_offsets.get(path, 0)
            if file_size < last_offset:
                last_offset = 0
            if last_offset == 0 and file_size > max_bytes:
                f.seek(file_size - max_bytes)
            else:
                f.seek(last_offset)
            data = f.read(max_bytes)
            _file_offsets[path] = f.tell()
    except Exception as exc:
        log("log_file_read_failed", path=path, error=str(exc))
        return []

    if not data:
        return []
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-max_lines:]


def collect_nginx_logs(interval_sec: int) -> list[str]:
    # The interval is used to keep proportional line caps for short/long collection windows.
    line_cap = max(20, min(80, interval_sec * 2))
    lines: list[str] = []
    for path, prefix in [
        ("/var/log/nginx/error.log", "[error.log]"),
        ("/var/log/nginx/access.log", "[access.log]"),
    ]:
        for line in _read_new_file_lines(path, max_bytes=200_000, max_lines=line_cap):
            lines.append(f"{prefix} {line}")
    return lines[-120:]


def _collect_system_file_logs(interval_sec: int) -> list[str]:
    line_cap = max(30, min(120, interval_sec * 4))
    lines: list[str] = []
    for path, prefix in [
        ("/var/log/syslog", "[syslog]"),
        ("/var/log/messages", "[messages]"),
        ("/var/log/auth.log", "[auth]"),
        ("/var/log/kern.log", "[kern]"),
    ]:
        for line in _read_new_file_lines(path, max_bytes=300_000, max_lines=line_cap):
            lines.append(f"{prefix} {line}")
    return lines[-200:]


def collect_docker_log_lines(interval_sec: int, containers: list[dict[str, Any]]) -> list[str]:
    target_containers: list[dict[str, Any]] = []
    for container in containers:
        status = str(container.get("status", "")).lower()
        if "restart" in status or "exited" in status or "unhealthy" in status:
            target_containers.append(container)
    if not target_containers:
        target_containers = containers[:2]
    target_containers = target_containers[:5]

    lines: list[str] = []
    since_arg = f"{max(15, int(interval_sec))}s"
    for container in target_containers:
        container_id = str(container.get("id", "")).strip()
        container_name = str(container.get("name", "")).strip() or container_id[:12]
        if not container_id:
            continue
        proc = _run_command(
            ["docker", "logs", "--tail", "40", "--since", since_arg, container_id],
            timeout=8,
        )
        if not proc or proc.returncode != 0:
            continue
        merged = "\n".join([proc.stdout or "", proc.stderr or ""]).strip()
        for line in merged.splitlines():
            msg = line.strip()
            if not msg:
                continue
            lines.append(f"[{container_name}] {msg}")

    if not lines:
        for path in ("/var/log/docker.log", "/var/log/daemon.log"):
            for line in _read_new_file_lines(path, max_bytes=250_000, max_lines=80):
                lower = line.lower()
                if "docker" in lower or "container" in lower:
                    lines.append(f"[engine] {line}")

    if not lines and containers:
        for container in containers[:8]:
            container_id = str(container.get("id", "")).strip()[:12]
            container_name = str(container.get("name", "")).strip() or container_id or "container"
            image = str(container.get("image", "")).strip()
            status = str(container.get("status", "")).strip()
            lines.append(f"[{container_name}] status={status} image={image} id={container_id}")
    return lines[-160:]


def collect_systemd_logs(units: list[str], interval_sec: int) -> dict[str, list[str]]:
    systemd_logs: dict[str, list[str]] = {}
    has_journalctl = bool(shutil.which("journalctl"))
    if has_journalctl:
        since_arg = f"-{int(interval_sec)} seconds"
        for unit in units:
            unit = unit.strip()
            if not unit:
                continue
            proc = _run_command(
                [
                    "journalctl",
                    "-u",
                    unit,
                    "--since",
                    since_arg,
                    "--no-pager",
                    "-n",
                    "200",
                    "-o",
                    "short-iso",
                ],
                timeout=6,
            )
            if not proc or proc.returncode != 0:
                continue
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            if lines:
                systemd_logs[unit] = lines

    if not systemd_logs:
        fallback_lines = _collect_system_file_logs(interval_sec)
        if fallback_lines:
            systemd_logs["system"] = fallback_lines
    return systemd_logs


def build_payload(interval_sec: int, units: list[str]) -> dict[str, Any]:
    docker_data = collect_docker(interval_sec)
    systemd_logs = collect_systemd_logs(units, interval_sec)
    nginx_logs = collect_nginx_logs(interval_sec)
    docker_log_lines = collect_docker_log_lines(interval_sec, docker_data.get("containers", []))

    return {
        "ts": now_iso(),
        "host": collect_host(),
        "metrics": collect_metrics(),
        "docker": docker_data,
        "logs": {
            "systemd": systemd_logs,
            "nginx": nginx_logs,
            "docker": docker_log_lines,
        },
    }


def _ingest_base_url(ingest_url: str) -> str:
    value = ingest_url.strip().rstrip("/")
    suffix = "/v1/ingest"
    if value.endswith(suffix):
        return value[: -len(suffix)]
    return value


def _collect_self_check(units: list[str], tags: dict[str, str]) -> dict[str, Any]:
    docker_proc = _run_command(["docker", "--version"], timeout=4)
    docker_version = ""
    if docker_proc and docker_proc.returncode == 0:
        docker_version = (docker_proc.stdout or docker_proc.stderr or "").strip()[:200]

    systemctl_available = bool(shutil.which("systemctl"))
    journalctl_available = bool(shutil.which("journalctl"))
    nginx_paths = [path for path in ["/var/log/nginx", "/host_etc_nginx", "/etc/nginx"] if os.path.exists(path)]

    return {
        "docker_version": docker_version or None,
        "systemd_available": systemctl_available,
        "journalctl_access": journalctl_available,
        "nginx_paths": nginx_paths,
        "supports_docker": bool(docker_version),
        "supports_nginx_logs": bool(nginx_paths),
        "supports_systemd_logs": "systemd" in [u.lower() for u in units] or "ssh" in [u.lower() for u in units],
        "supports_journalctl_logs": journalctl_available,
        "tags": tags,
        "metadata": {
            "hostname": platform.node(),
            "units": units,
        },
    }


def send_self_check(
    *,
    session: requests.Session,
    ingest_url: str,
    agent_token: str,
    units: list[str],
    tags: dict[str, str],
) -> None:
    endpoint = _ingest_base_url(ingest_url) + "/v1/agent/self-check"
    payload = _collect_self_check(units, tags)
    try:
        resp = session.post(
            endpoint,
            json=payload,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=8,
        )
        log(
            "self_check_response",
            status_code=resp.status_code,
            ok=resp.ok,
            response_text=(resp.text[:300] if resp.text else ""),
        )
    except Exception as exc:
        log("self_check_error", error=str(exc))


def main() -> None:
    ingest_url = env_required("INGEST_URL")
    agent_token = env_required("AGENT_TOKEN")
    interval_sec = int(os.getenv("INTERVAL_SEC", "15"))
    units = [u.strip() for u in os.getenv("SYSTEMD_UNITS", "nginx,ssh,docker").split(",") if u.strip()]
    tags = _parse_agent_tags()

    # Warm up psutil CPU sampling so the first sent value is more useful.
    psutil.cpu_percent(interval=None)

    session = requests.Session()
    backoff_sec = 1
    cycles = 0

    send_self_check(
        session=session,
        ingest_url=ingest_url,
        agent_token=agent_token,
        units=units,
        tags=tags,
    )
    log("agent_started", ingest_url=ingest_url, interval_sec=interval_sec, units=units, tags=tags)
    while True:
        try:
            payload = build_payload(interval_sec, units)
            resp = session.post(
                ingest_url,
                json=payload,
                headers={"Authorization": f"Bearer {agent_token}"},
                timeout=10,
            )
            log(
                "ingest_response",
                status_code=resp.status_code,
                ok=resp.ok,
                response_text=(resp.text[:500] if resp.text else ""),
            )
            if not (200 <= resp.status_code < 300):
                raise RuntimeError(f"HTTP {resp.status_code}")
            cycles += 1
            if cycles % 30 == 0:
                send_self_check(
                    session=session,
                    ingest_url=ingest_url,
                    agent_token=agent_token,
                    units=units,
                    tags=tags,
                )
            backoff_sec = 1
            time.sleep(interval_sec)
        except Exception as exc:
            log("ingest_error", error=str(exc), backoff_sec=backoff_sec)
            time.sleep(backoff_sec)
            backoff_sec = min(60, max(1, backoff_sec * 2))


if __name__ == "__main__":
    main()
