from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

import psutil
import requests


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


def collect_host() -> dict[str, str]:
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
    }


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
    ps_proc = _run_command(["docker", "ps", "--format", "{{json .}}"], timeout=5)
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


def collect_systemd_logs(units: list[str], interval_sec: int) -> dict[str, Any]:
    systemd_logs: dict[str, list[str]] = {}
    if not shutil.which("journalctl"):
        return {"systemd": systemd_logs}

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
    return {"systemd": systemd_logs}


def build_payload(interval_sec: int, units: list[str]) -> dict[str, Any]:
    return {
        "ts": now_iso(),
        "host": collect_host(),
        "metrics": collect_metrics(),
        "docker": collect_docker(interval_sec),
        "logs": collect_systemd_logs(units, interval_sec),
    }


def main() -> None:
    ingest_url = env_required("INGEST_URL")
    agent_token = env_required("AGENT_TOKEN")
    interval_sec = int(os.getenv("INTERVAL_SEC", "15"))
    units = [u.strip() for u in os.getenv("SYSTEMD_UNITS", "nginx,ssh").split(",") if u.strip()]

    # Warm up psutil CPU sampling so the first sent value is more useful.
    psutil.cpu_percent(interval=None)

    session = requests.Session()
    backoff_sec = 1

    log("agent_started", ingest_url=ingest_url, interval_sec=interval_sec, units=units)
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
            backoff_sec = 1
            time.sleep(interval_sec)
        except Exception as exc:
            log("ingest_error", error=str(exc), backoff_sec=backoff_sec)
            time.sleep(backoff_sec)
            backoff_sec = min(60, max(1, backoff_sec * 2))


if __name__ == "__main__":
    main()
