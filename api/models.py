from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ServerCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        stripped = value.strip()
        if len(stripped) < 2:
            raise ValueError("name must be at least 2 characters")
        return stripped


class ServerCreateResponse(BaseModel):
    server_id: UUID
    name: str
    agent_token: str
    install_command: str


class ServerListItem(BaseModel):
    server_id: UUID
    name: str
    status: str
    last_seen_at: datetime | None
    created_at: datetime


class MetricSummary(BaseModel):
    ts: datetime
    cpu_percent: float | None = None
    ram_percent: float | None = None
    disk_percent: float | None = None
    load1: float | None = None
    load5: float | None = None
    load15: float | None = None
    net_bytes_sent: int | None = None
    net_bytes_recv: int | None = None


class AlertItem(BaseModel):
    id: int
    server_id: UUID
    ts: datetime
    type: str
    severity: str
    title: str
    details: dict[str, Any]
    is_resolved: bool
    resolved_at: datetime | None


class ServerDetailResponse(BaseModel):
    server_id: UUID
    name: str
    status: str
    created_at: datetime
    last_seen_at: datetime | None
    metadata: dict[str, Any]
    last_metrics: MetricSummary | None
    alerts: list[AlertItem]


class HostInfo(BaseModel):
    hostname: str | None = None
    os: str | None = None
    os_release: str | None = None
    machine: str | None = None


class MetricsPayload(BaseModel):
    cpu_percent: float | None = None
    ram_percent: float | None = None
    disk_percent: float | None = None
    loadavg: list[float] = Field(default_factory=list, max_length=3)
    net_bytes_sent: int | None = None
    net_bytes_recv: int | None = None


class DockerContainerPayload(BaseModel):
    id: str = ""
    image: str = ""
    name: str = ""
    status: str = ""


class DockerPayload(BaseModel):
    containers: list[DockerContainerPayload] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class LogsPayload(BaseModel):
    systemd: dict[str, list[str]] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    ts: datetime
    host: HostInfo = Field(default_factory=HostInfo)
    metrics: MetricsPayload
    docker: DockerPayload = Field(default_factory=DockerPayload)
    logs: LogsPayload = Field(default_factory=LogsPayload)


class IngestResponse(BaseModel):
    ok: bool = True
    server_id: UUID
    alerts_created: list[str] = Field(default_factory=list)
    logs_inserted: int


class AlertsListResponse(BaseModel):
    items: list[AlertItem]


class HealthResponse(BaseModel):
    status: Literal["ok"]
