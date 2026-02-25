from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = Field(..., alias="DATABASE_URL")
    agent_token_pepper: str = Field(..., alias="AGENT_TOKEN_PEPPER")
    offline_after_seconds: int = Field(120, alias="OFFLINE_AFTER_SECONDS")
    alert_dedupe_seconds: int = Field(600, alias="ALERT_DEDUPE_SECONDS")
    app_public_install_sh_url: str = Field(..., alias="APP_PUBLIC_INSTALL_SH_URL")
    api_base_url: str = Field(..., alias="API_BASE_URL")
    ip_rate_limit_per_minute: int = 60
    agent_rate_limit_per_minute: int = 120
    offline_check_interval_seconds: int = 60
    json_log_level: str = "INFO"
    smtp_host: str | None = Field(default=None, alias="SMTP_HOST")
    smtp_port: int = Field(587, alias="SMTP_PORT")
    smtp_user: str | None = Field(default=None, alias="SMTP_USER")
    smtp_pass: str | None = Field(default=None, alias="SMTP_PASS")
    smtp_from: str | None = Field(default=None, alias="SMTP_FROM")
    smtp_tls: bool = Field(True, alias="SMTP_TLS")
    send_recovery_emails: bool = Field(False, alias="SEND_RECOVERY_EMAILS")
    uptime_slow_threshold_ms: int = Field(2000, alias="UPTIME_SLOW_THRESHOLD_MS")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
