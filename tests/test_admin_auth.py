"""Phase 1 administrator authentication and security acceptance tests."""

from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.admin import AdminUser


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
USERNAME = "admin"
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login_csrf(client: TestClient) -> str:
    response = client.get("/admin/login")
    assert response.status_code == 200
    match = LOGIN_CSRF_PATTERN.search(response.text)
    assert match, "login form must contain a CSRF token"
    return match.group(1)


def _login(client: TestClient, *, password: str = PASSWORD, totp: str | None = None):
    csrf_token = _login_csrf(client)
    return client.post(
        "/admin/login",
        data={
            "username": USERNAME,
            "password": password,
            "totp": totp or pyotp.TOTP(TOTP_SECRET).now(),
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )


def test_b01_unauthenticated_admin_is_redirected_to_login(client: TestClient) -> None:
    response = client.get("/admin/people", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/admin/login")
    assert "测试角色" not in response.text


def test_b02_admin_can_login_and_session_persists(client: TestClient) -> None:
    response = _login(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    set_cookie = response.headers["set-cookie"]
    assert "still_alive_admin_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie

    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert "系统总览" in dashboard.text
    assert "Public Delivery" in dashboard.text
    assert "可用" in dashboard.text

    refreshed = client.get("/admin")
    assert refreshed.status_code == 200
    assert "管理员登录" not in refreshed.text


def test_b02_production_https_cookie_is_secure(configured_environment, monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RELEASE_RUNTIME_MODE", "strict")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://testserver")
    from app.main import create_app

    with TestClient(create_app(), base_url="https://testserver") as production_client:
        response = _login(production_client)
        assert response.status_code == 303
        assert "still_alive_admin_session=" in response.headers["set-cookie"]
        assert "Secure" in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "SameSite=strict" in response.headers["set-cookie"]


def test_b03_wrong_password_and_totp_are_generic_failures(client: TestClient) -> None:
    wrong_password = _login(client, password="definitely-wrong-password")
    assert wrong_password.status_code == 401
    assert "用户名、密码或动态验证码不正确" in wrong_password.text
    assert "TOTP" not in wrong_password.text

    wrong_totp = _login(client, totp="000000")
    assert wrong_totp.status_code == 401
    assert "用户名、密码或动态验证码不正确" in wrong_totp.text
    assert PASSWORD not in wrong_totp.text


def test_csrf_and_csp_are_enforced(client: TestClient) -> None:
    login_page = client.get("/admin/login")
    assert "default-src 'self'" in login_page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in login_page.headers["content-security-policy"]

    assert _login(client).status_code == 303
    csrf_failure = client.post("/admin/logout", data={"csrf_token": "wrong-token"}, follow_redirects=False)
    assert csrf_failure.status_code == 403


def test_audit_contains_events_without_password_or_totp(client: TestClient) -> None:
    _login(client, password="bad-password-for-audit")
    assert _login(client).status_code == 303
    audit = client.get("/admin/audit")
    assert audit.status_code == 200
    assert "admin.login.failed" in audit.text
    assert "admin.login.success" in audit.text
    assert "bad-password-for-audit" not in audit.text
    assert TOTP_SECRET not in audit.text


def test_admin_secrets_are_not_stored_in_plaintext(client: TestClient) -> None:
    with client.app.state.session_factory() as db:
        admin = db.scalar(select(AdminUser).where(AdminUser.username == USERNAME))
    assert admin is not None
    assert admin.password_hash.startswith("$argon2id$")
    assert PASSWORD not in admin.password_hash
    assert admin.totp_secret_ciphertext != TOTP_SECRET.encode("utf-8")
    assert admin.totp_secret_nonce
