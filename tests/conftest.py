"""Shared Phase 0 test fixtures."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient


def _set_valid_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("RELEASE_RUNTIME_MODE", "source_fallback")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'app.db'}")
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"m" * 32).decode("ascii"))
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "CorrectHorseBatteryStaple!")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
    monkeypatch.setenv("INTEGRITY_INCREMENTAL_SIMULATIONS_PER_PERSON", "5")
    monkeypatch.setenv("INTEGRITY_SEAL_SIMULATIONS_PER_PERSON", "10")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "vault"))
    monkeypatch.setenv("RELEASE_PATH", str(tmp_path / "releases"))


@pytest.fixture
def configured_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    _set_valid_environment(monkeypatch, tmp_path)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'app.db'}")
    command.upgrade(config, "head")
    return tmp_path


@pytest.fixture
def client(configured_environment: Path) -> TestClient:
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
