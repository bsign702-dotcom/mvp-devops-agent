from __future__ import annotations

from datetime import datetime, time
from typing import Any, Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


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
    server_id: UUID | None = None
    uptime_monitor_id: UUID | None = None
    ts: datetime
    type: str
    severity: str
    title: str
    details: dict[str, Any]
    is_resolved: bool
    resolved_at: datetime | None


class ServerLogItem(BaseModel):
    ts: datetime
    source: str
    level: str
    message: str


class ServerDetailResponse(BaseModel):
    server_id: UUID
    name: str
    status: str
    created_at: datetime
    last_seen_at: datetime | None
    metadata: dict[str, Any]
    ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    primary_ip: str | None = None
    docker_containers: list[dict[str, Any]] = Field(default_factory=list)
    log_sources: dict[str, int] = Field(default_factory=dict)
    recent_logs: list[ServerLogItem] = Field(default_factory=list)
    agent_capabilities: dict[str, Any] = Field(default_factory=dict)
    last_heartbeat_at: datetime | None = None
    heartbeat_status: str | None = None
    last_metrics: MetricSummary | None
    alerts: list[AlertItem]


class ServerDeleteResponse(BaseModel):
    ok: bool = True
    server_id: UUID
    deleted: bool = True


class UptimeMonitorCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    url: AnyHttpUrl
    check_interval_sec: int = Field(30, ge=10, le=3600)
    timeout_sec: int = Field(10, ge=1, le=60)
    expected_status: int = Field(200, ge=100, le=599)

    @field_validator("name")
    @classmethod
    def _strip_monitor_name(cls, value: str) -> str:
        stripped = value.strip()
        if len(stripped) < 2:
            raise ValueError("name must be at least 2 characters")
        return stripped


class UptimeMonitorItem(BaseModel):
    id: UUID
    name: str
    url: str
    check_interval_sec: int
    timeout_sec: int
    expected_status: int
    last_status: str
    last_response_time_ms: int | None = None
    last_checked_at: datetime | None = None
    consecutive_failures: int
    created_at: datetime


class UptimeMonitorDeleteResponse(BaseModel):
    ok: bool = True
    monitor_id: UUID
    deleted: bool = True


class UptimeCheckItem(BaseModel):
    id: int
    monitor_id: UUID
    status: str
    response_time_ms: int | None = None
    status_code: int | None = None
    error_message: str | None = None
    checked_at: datetime


class NotificationSettingUpsertRequest(BaseModel):
    email: str
    is_enabled: bool = True
    cpu_threshold: int = Field(80, ge=1, le=100)
    disk_threshold: int = Field(85, ge=1, le=100)
    ram_threshold: int = Field(85, ge=1, le=100)
    offline_threshold_sec: int = Field(120, ge=30, le=86400)
    daily_report_time_utc: str = Field("08:00")

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or "." not in value.split("@")[-1]:
            raise ValueError("invalid email")
        return value

    @field_validator("daily_report_time_utc")
    @classmethod
    def _validate_daily_time(cls, value: str) -> str:
        parts = value.strip().split(":")
        if len(parts) != 2:
            raise ValueError("daily_report_time_utc must be HH:MM")
        hour = int(parts[0])
        minute = int(parts[1])
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError("daily_report_time_utc must be HH:MM")
        return f"{hour:02d}:{minute:02d}"


class NotificationSettingItem(BaseModel):
    id: UUID
    email: str
    is_enabled: bool
    cpu_threshold: int
    disk_threshold: int
    ram_threshold: int
    offline_threshold_sec: int
    daily_report_time_utc: time
    created_at: datetime


class NotificationTestEmailRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or "." not in value.split("@")[-1]:
            raise ValueError("invalid email")
        return value


class NotificationTestEmailResponse(BaseModel):
    ok: bool = True
    email: str
    message: str = "Test email sent"


class UserMeResponse(BaseModel):
    user_id: UUID
    supabase_user_id: UUID
    email: str
    full_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HostInfo(BaseModel):
    hostname: str | None = None
    os: str | None = None
    os_release: str | None = None
    machine: str | None = None
    primary_ip: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)


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
    nginx: list[str] = Field(default_factory=list)
    docker: list[str] = Field(default_factory=list)


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


class ChatSessionCreateRequest(BaseModel):
    server_id: UUID
    title: str | None = Field(default=None, max_length=120)

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        return stripped


class ChatSessionItem(BaseModel):
    id: UUID
    server_id: UUID
    title: str
    mode: Literal["suggest_only"]
    created_at: datetime
    updated_at: datetime
    last_message_at: datetime | None = None


class ChatMessageCreateRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("message is required")
        return stripped


class ChatMessageItem(BaseModel):
    id: int
    session_id: UUID
    role: Literal["user", "assistant", "system"]
    content: str
    created_at: datetime


class ChatAskResponse(BaseModel):
    session_id: UUID
    mode: Literal["suggest_only"]
    model: str
    user_message: ChatMessageItem
    assistant_message: ChatMessageItem


class HealthResponse(BaseModel):
    status: Literal["ok"]


class StackItem(BaseModel):
    id: str
    name: str
    description: str


class StackDetailResponse(BaseModel):
    id: str
    name: str
    description: str
    required_inputs: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    required_agent_capabilities: list[str] = Field(default_factory=list)


class ProvisionPlanFile(BaseModel):
    path: str
    content: str


class ProvisionPlanCreateRequest(BaseModel):
    stack_id: str = Field(
        ...,
        min_length=1,
        max_length=120,
        json_schema_extra={"example": "docker-nginx-basic"},
    )
    inputs: dict[str, Any] = Field(default_factory=dict)


class ProvisionPlanResponse(BaseModel):
    plan_id: UUID
    server_id: UUID
    stack_id: str
    files: list[ProvisionPlanFile] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class PreflightCheckItem(BaseModel):
    key: str
    title: str
    command: str
    expected: str
    required: bool = True


class PreflightCreateRequest(BaseModel):
    stack_id: str | None = Field(default=None, max_length=120)
    inputs: dict[str, Any] = Field(default_factory=dict)


class PreflightCreateResponse(BaseModel):
    run_id: UUID
    server_id: UUID
    status: Literal["pending", "incomplete", "ready"]
    checklist: list[PreflightCheckItem] = Field(default_factory=list)


class PreflightResultsRequest(BaseModel):
    run_id: UUID | None = None
    results: dict[str, str] = Field(default_factory=dict)


class PreflightResultsResponse(BaseModel):
    run_id: UUID
    server_id: UUID
    status: Literal["pending", "incomplete", "ready"]
    missing_items: list[str] = Field(default_factory=list)
    submitted_results: dict[str, str] = Field(default_factory=dict)


class StructuredLogEntry(BaseModel):
    id: int
    ts: datetime
    source: str
    service: str | None = None
    level: str
    message: str
    fingerprint: str
    tags: list[str] = Field(default_factory=list)


class FingerprintAggregate(BaseModel):
    fingerprint: str
    count: int
    sample_message: str


class NameCount(BaseModel):
    name: str
    count: int


class LogSearchResponse(BaseModel):
    items: list[StructuredLogEntry] = Field(default_factory=list)
    by_fingerprint: list[FingerprintAggregate] = Field(default_factory=list)
    top_sources: list[NameCount] = Field(default_factory=list)
    top_services: list[NameCount] = Field(default_factory=list)


class MetricsHistoryPoint(BaseModel):
    bucket_ts: datetime
    cpu_avg: float | None = None
    ram_avg: float | None = None
    disk_avg: float | None = None
    load1_avg: float | None = None
    net_sent_max: int | None = None
    net_recv_max: int | None = None
    sample_count: int


class MetricsHistoryResponse(BaseModel):
    server_id: UUID
    bucket: Literal["1m", "5m", "1h"]
    points: list[MetricsHistoryPoint] = Field(default_factory=list)


class TimelineEventItem(BaseModel):
    ts: datetime
    category: str
    source: str
    title: str
    severity: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    server_id: UUID
    items: list[TimelineEventItem] = Field(default_factory=list)


class ProjectTemplateItem(BaseModel):
    id: str
    name: str
    kind: str
    description: str


class ProjectTemplateDetail(BaseModel):
    id: str
    name: str
    kind: str
    description: str
    compose: str
    nginx_conf: str
    env_template: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComposeLintRequest(BaseModel):
    yaml: str = Field(
        ...,
        min_length=1,
        json_schema_extra={
            "example": "services:\\n  app:\\n    image: ghcr.io/example/app:1.0.0\\n    restart: unless-stopped\\n"
        },
    )


class NginxLintRequest(BaseModel):
    conf: str = Field(
        ...,
        min_length=1,
        json_schema_extra={
            "example": "server {\\n  listen 80;\\n  server_name app.example.com;\\n  location / { proxy_pass http://127.0.0.1:8000; }\\n}"
        },
    )


class LintResponse(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class TroubleshootingPacketResponse(BaseModel):
    server: dict[str, Any] = Field(default_factory=dict)
    identity: dict[str, Any] = Field(default_factory=dict)
    metrics_snapshot: dict[str, Any] = Field(default_factory=dict)
    metric_trend: dict[str, Any] = Field(default_factory=dict)
    recent_alerts: list[dict[str, Any]] = Field(default_factory=list)
    recent_logs: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    recent_docker_events: list[dict[str, Any]] = Field(default_factory=list)
    recent_provision_plans: list[dict[str, Any]] = Field(default_factory=list)
    agent_capabilities: dict[str, Any] = Field(default_factory=dict)


class AgentSelfCheckRequest(BaseModel):
    docker_version: str | None = None
    systemd_available: bool = False
    journalctl_access: bool = False
    nginx_paths: list[str] = Field(default_factory=list)
    supports_docker: bool = False
    supports_nginx_logs: bool = False
    supports_systemd_logs: bool = False
    supports_journalctl_logs: bool = False
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentSelfCheckResponse(BaseModel):
    ok: bool = True
    server_id: UUID
    capabilities: dict[str, Any] = Field(default_factory=dict)
