"""Typed configuration loaded from environment variables.

Settings fail fast: a staging or production process refuses to start without a
JWT signing key, a database URL and a Redis URL.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            return json.loads(stripped)
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # ------------------------------------------------------------------ app
    environment: Environment = "local"
    app_name: str = "Auth and API Platform"
    public_base_url: str = "http://localhost:8000"
    log_level: str = "INFO"
    log_json: bool = True

    # ------------------------------------------------------------------ data stores
    database_url: SecretStr = SecretStr("postgresql+asyncpg://auth:auth@localhost:5432/auth")
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_echo: bool = False
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # ------------------------------------------------------------------ JWT
    jwt_private_key: SecretStr | None = None
    jwt_private_key_file: Path | None = None
    # JSON list of PEM public keys that were used before the last rotation.
    jwt_previous_public_keys: Annotated[list[str], NoDecode] = Field(default_factory=list)
    jwt_issuer: str = "auth-platform"
    jwt_audience: str = "auth-platform-api"
    access_token_ttl_seconds: int = 15 * 60
    mfa_token_ttl_seconds: int = 5 * 60
    refresh_token_ttl_days: int = 14
    verify_email_ttl_hours: int = 24
    password_reset_ttl_minutes: int = 30

    # Refresh-token cookie for browser clients (API clients use the response body).
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_secure: bool = True
    refresh_cookie_path: str = "/v1/auth"

    # ------------------------------------------------------------------ passwords
    argon2_time_cost: int = 2
    argon2_memory_cost_kib: int = 19456
    argon2_parallelism: int = 1
    password_min_length: int = 12
    password_max_length: int = 128
    require_verified_email: bool = True

    # ------------------------------------------------------------------ brute force / rate limits
    lockout_threshold: int = 5
    lockout_base_seconds: int = 60
    lockout_max_seconds: int = 3600
    rate_limit_enabled: bool = True
    global_rate_limit: int = 300  # requests per window per IP
    global_rate_window_seconds: int = 60
    login_rate_limit: int = 10  # login attempts per window per IP
    login_rate_window_seconds: int = 60
    login_ip_failure_limit: int = 20  # failed logins per window per IP
    login_ip_failure_window_seconds: int = 900
    register_rate_limit: int = 5
    register_rate_window_seconds: int = 600
    forgot_rate_limit: int = 5
    forgot_rate_window_seconds: int = 900

    # ------------------------------------------------------------------ HTTP
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    metrics_allowed_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "127.0.0.1/32",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    metrics_bearer_token: SecretStr | None = None
    idempotency_ttl_hours: int = 24
    # Role -> permission map cached in-process; 0 disables (one DB query per request).
    permission_cache_ttl_seconds: float = 60.0
    docs_enabled: bool = True

    # ------------------------------------------------------------------ email
    email_backend: Literal["console", "smtp", "memory"] = "console"
    email_from: str = "no-reply@auth-platform.local"
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True

    # ------------------------------------------------------------------ demo account
    demo_email: str | None = None
    demo_read_only: bool = False

    # ------------------------------------------------------------------ MFA (stretch)
    mfa_issuer: str = "Auth Platform"
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt TOTP secrets at rest.
    mfa_encryption_key: SecretStr | None = None

    # ------------------------------------------------------------------ Google sign-in (stretch)
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    google_redirect_uri: str | None = None

    # ------------------------------------------------------------------ telemetry
    otel_enabled: bool = False
    otel_service_name: str = "auth-platform"
    otel_exporter_otlp_endpoint: str | None = None

    @field_validator(
        "cors_origins", "metrics_allowed_cidrs", "jwt_previous_public_keys", mode="before"
    )
    @classmethod
    def _parse_lists(cls, value: object) -> object:
        return _split_csv(value)

    @model_validator(mode="after")
    def _fail_fast(self) -> Settings:
        if self.environment in {"staging", "production"}:
            if self.jwt_private_key is None and self.jwt_private_key_file is None:
                raise ValueError("JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE is required")
            if self.email_backend == "console":
                raise ValueError("EMAIL_BACKEND=console is not allowed outside local/test")
            if "*" in self.cors_origins:
                raise ValueError("CORS wildcard is not allowed with credentials")
        return self

    @property
    def is_production_like(self) -> bool:
        return self.environment in {"staging", "production"}

    def load_private_key_pem(self) -> str | None:
        if self.jwt_private_key is not None:
            return self.jwt_private_key.get_secret_value().replace("\\n", "\n")
        if self.jwt_private_key_file is not None:
            return self.jwt_private_key_file.read_text()
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
