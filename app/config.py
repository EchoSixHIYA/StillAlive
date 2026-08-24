"""Application configuration and startup validation."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import pyotp
from pydantic import AnyHttpUrl, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime settings.

    Secrets intentionally have no usable defaults. A missing or placeholder
    secret must stop application startup instead of silently generating one.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "test", "production"] = "development"
    release_runtime_mode: Literal["strict", "source_fallback"] = "strict"
    database_url: str = "sqlite:///./data/app.db"
    master_key: SecretStr | None = None
    answer_pepper: SecretStr | None = None
    session_secret: SecretStr | None = None
    admin_auth_secret: SecretStr | None = None
    admin_bootstrap_username: str = "admin"
    admin_bootstrap_password: SecretStr | None = None
    admin_bootstrap_totp_secret: SecretStr | None = None
    public_base_url: AnyHttpUrl = "http://localhost:8000"
    vault_path: Path = Path("./data/vault")
    release_path: Path = Path("./data/releases")
    admin_session_idle_minutes: int = 15
    admin_session_absolute_hours: int = 8
    download_grant_ttl_seconds: int = 600
    download_grant_max_uses: int = 1
    asset_max_upload_bytes: int = 10 * 1024 * 1024
    rate_limit_enabled: bool = True
    identity_max_questions: int = 15
    discovery_session_minutes: int = 30
    identity_blocking_confusion_rate: float = 0.01
    identity_warning_confusion_rate: float = 0.0025
    integrity_incremental_simulations_per_person: int = 500
    integrity_seal_simulations_per_person: int = 5000

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        if not value or "://" not in value:
            raise ValueError("DATABASE_URL must be a valid SQLAlchemy URL")
        return value

    @field_validator(
        "admin_session_idle_minutes",
        "admin_session_absolute_hours",
        "download_grant_ttl_seconds",
        "download_grant_max_uses",
        "asset_max_upload_bytes",
        "identity_max_questions",
        "discovery_session_minutes",
        "integrity_incremental_simulations_per_person",
        "integrity_seal_simulations_per_person",
    )
    @classmethod
    def validate_positive_integer(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be greater than zero")
        return value

    @field_validator("identity_blocking_confusion_rate", "identity_warning_confusion_rate")
    @classmethod
    def validate_rate(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("must be between 0 and 1")
        return value

    @field_validator("admin_bootstrap_username")
    @classmethod
    def validate_bootstrap_username(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 128:
            raise ValueError("ADMIN_BOOTSTRAP_USERNAME must be 1-128 characters")
        return value

    @model_validator(mode="after")
    def validate_required_secrets(self) -> Settings:
        required = {
            "MASTER_KEY": self.master_key,
            "ANSWER_PEPPER": self.answer_pepper,
            "SESSION_SECRET": self.session_secret,
            "ADMIN_AUTH_SECRET": self.admin_auth_secret,
        }
        missing = [name for name, value in required.items() if self._is_placeholder(value)]
        if missing:
            raise ValueError("missing or placeholder required secret(s): " + ", ".join(missing))

        master_key_bytes = self.master_key_bytes
        if len(master_key_bytes) != 32:
            raise ValueError("MASTER_KEY must be base64-encoded 32 bytes")
        bootstrap_password = self.admin_bootstrap_password
        bootstrap_totp = self.admin_bootstrap_totp_secret
        if (bootstrap_password is None) != (bootstrap_totp is None):
            raise ValueError("ADMIN_BOOTSTRAP_PASSWORD and ADMIN_BOOTSTRAP_TOTP_SECRET must be provided together")
        if bootstrap_password is not None and bootstrap_totp is not None:
            if self._is_placeholder(bootstrap_password) or self._is_placeholder(bootstrap_totp):
                raise ValueError("ADMIN bootstrap secrets must not use example placeholders")
            if len(bootstrap_password.get_secret_value()) < 12:
                raise ValueError("ADMIN_BOOTSTRAP_PASSWORD must contain at least 12 characters")
            try:
                pyotp.TOTP(bootstrap_totp.get_secret_value().strip().replace(" ", "")).now()
            except Exception as exc:
                raise ValueError("ADMIN_BOOTSTRAP_TOTP_SECRET must be a valid base32 TOTP secret") from exc
        if self.app_env == "production" and str(self.public_base_url).startswith("http://"):
            hostname = (urlsplit(str(self.public_base_url)).hostname or "").lower()
            if hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("PUBLIC_BASE_URL must use HTTPS in production unless it is loopback-only")
        if self.app_env == "production" and self.release_runtime_mode != "strict":
            raise ValueError("RELEASE_RUNTIME_MODE must be strict in production")
        return self

    @staticmethod
    def _is_placeholder(value: SecretStr | None) -> bool:
        if value is None:
            return True
        raw = value.get_secret_value().strip()
        return not raw or raw.startswith("replace_with_") or raw.startswith("change_me")

    @property
    def master_key_bytes(self) -> bytes:
        """Decode the 32-byte AES master key without exposing it in repr/logs."""

        if self.master_key is None:
            raise ValueError("MASTER_KEY is required")
        raw = self.master_key.get_secret_value().strip()
        try:
            return base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("MASTER_KEY must be valid base64") from exc

    def ensure_runtime_directories(self) -> None:
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.release_path.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            database_path = self.database_url.removeprefix("sqlite:///")
            if database_path != ":memory:":
                Path(database_path).parent.mkdir(parents=True, exist_ok=True)


def configuration_error_message(exc: ValidationError) -> str:
    """Return a concise startup error that identifies the invalid setting."""

    messages = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "settings"
        messages.append(f"{location}: {error.get('msg', 'invalid value')}")
    return "Configuration error: " + "; ".join(messages)
