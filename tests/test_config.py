"""Configuration acceptance tests."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError


def test_master_key_is_decoded_to_exactly_32_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import Settings

    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    settings = Settings()
    assert settings.master_key_bytes == b"k" * 32


def test_missing_master_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import Settings

    monkeypatch.delenv("MASTER_KEY", raising=False)
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    with pytest.raises(ValidationError, match="MASTER_KEY"):
        Settings(_env_file=None)


def test_production_requires_strict_release_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import Settings

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RELEASE_RUNTIME_MODE", "source_fallback")
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"m" * 32).decode("ascii"))
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://still-alive.example")

    with pytest.raises(ValidationError, match="RELEASE_RUNTIME_MODE"):
        Settings(_env_file=None)


def test_production_loopback_http_is_allowed_for_offline_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import Settings

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RELEASE_RUNTIME_MODE", "strict")
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"m" * 32).decode("ascii"))
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000")

    settings = Settings(_env_file=None)
    from app.security.admin_auth import cookie_is_secure

    assert cookie_is_secure(settings) is False
