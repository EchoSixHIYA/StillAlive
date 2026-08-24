"""J/K acceptance tests and explicit Phase 9 scope guards."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.grant import DownloadGrant
from app.models.identity import Person
from app.security.rate_limit import InMemoryRateLimiter


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login(client: TestClient) -> None:
    page = client.get("/admin/login")
    token = LOGIN_CSRF_PATTERN.search(page.text).group(1)
    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def test_j01_audit_page_supports_event_filter(client: TestClient) -> None:
    _login(client)
    response = client.get("/admin/audit?event_type=admin.login.success")
    assert response.status_code == 200
    assert "admin.login.success" in response.text
    assert "admin.login.failed" not in response.text


def test_j02_request_logs_are_structured_and_redact_download_token(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="still_alive.request")
    raw_token = "raw-token-must-not-be-logged"
    health = client.get("/health/live")
    assert health.status_code == 200
    response = client.get(f"/download/{raw_token}")
    assert response.status_code == 404
    records = [record.message for record in caplog.records if record.name == "still_alive.request"]
    assert records
    payload = json.loads(records[0])
    assert {"timestamp", "level", "request_id", "route", "event", "status_code", "duration_ms"} <= payload.keys()
    assert any(json.loads(record)["route"] == "/download/{token}" for record in records)
    assert raw_token not in "\n".join(records)


def test_phase9_public_origin_and_rate_limit_guards(client: TestClient) -> None:
    origin_rejected = client.post("/api/public/sessions", headers={"Origin": "https://evil.example"})
    assert origin_rejected.status_code == 403

    limiter = InMemoryRateLimiter()
    limiter.check("test-key", limit=1, window_seconds=60)
    with pytest.raises(HTTPException) as error:
        limiter.check("test-key", limit=1, window_seconds=60)
    assert error.value.status_code == 429


def test_phase9_asset_disable_and_grant_revoke_are_audited(client: TestClient) -> None:
    _login(client)
    person_response = client.post(
        "/admin/people",
        data={"display_name": "测试角色A", "status": "active", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert person_response.status_code == 303
    person_id = person_response.headers["location"].rsplit("/", 1)[1]
    upload = client.post(
        f"/admin/people/{person_id}/assets",
        data={"display_name": "fixture.txt", "csrf_token": _csrf(client)},
        files={"file": ("fixture.txt", b"fixture", "text/plain")},
        follow_redirects=False,
    )
    assert upload.status_code == 303
    with client.app.state.session_factory() as db:
        asset = db.scalar(select(Asset).where(Asset.person_id == person_id))
        assert asset is not None
        asset_id = asset.id
    disabled = client.post(
        f"/admin/people/{person_id}/assets/{asset_id}/status",
        data={"active": "false", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert disabled.status_code == 303

    session_id = client.post("/api/public/sessions").json()["session_id"]
    with client.app.state.session_factory() as db:
        person = db.get(Person, person_id)
        assert person is not None
        grant = DownloadGrant(
            token_digest=b"r" * 32,
            session_id=session_id,
            person_id=person_id,
            asset_id=asset_id,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            downloads_remaining=1,
        )
        db.add(grant)
        db.commit()
        grant_id = grant.id
    revoked = client.post(f"/admin/grants/{grant_id}/revoke", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert revoked.status_code == 303
    with client.app.state.session_factory() as db:
        stored_asset = db.get(Asset, asset_id)
        stored_grant = db.get(DownloadGrant, grant_id)
        events = db.scalars(select(AuditEvent).where(AuditEvent.target_id.in_([asset_id, grant_id]))).all()
        assert stored_asset is not None and stored_asset.active is False
        assert stored_grant is not None and stored_grant.revoked_at is not None
        assert {event.event_type for event in events} >= {"asset.disabled", "grant.revoked"}


def test_phase9_future_lifecycle_scope_is_absent(client: TestClient) -> None:
    with client.app.state.db_engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert not tables.intersection({"heartbeat", "heartbeats", "trigger_policy", "trigger_policies", "lifecycle_state", "lifecycle_states"})
    paths = {route.path for route in client.app.routes if hasattr(route, "path")}
    assert not any(path.startswith("/api/admin/lifecycle") or path.startswith("/api/admin/heartbeat") for path in paths)
