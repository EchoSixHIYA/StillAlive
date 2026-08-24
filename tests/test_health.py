"""A-01/A-02 startup and health acceptance tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_a01_home_live_and_ready(client: TestClient) -> None:
    home = client.get("/")
    assert home.status_code == 200
    assert "Still Alive" in home.text
    assert "开始识别" in home.text

    live = client.get("/health/live")
    assert live.status_code == 200
    assert live.json() == {"status": "live"}

    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "checks": {
            "database": "ok",
            "vault": "ok",
            "release_storage": "ok",
            "secrets": "ok",
            "migrations": "ok",
        },
    }


def test_a02_missing_master_key_fails_application_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.delenv("MASTER_KEY", raising=False)
    monkeypatch.setenv("ANSWER_PEPPER", "a" * 48)
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("ADMIN_AUTH_SECRET", "d" * 48)
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")

    from app.main import create_app

    with pytest.raises(RuntimeError, match="MASTER_KEY"):
        with TestClient(create_app()):
            pass
