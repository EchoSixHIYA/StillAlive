"""H-series encrypted Asset/Vault acceptance tests."""

from __future__ import annotations

import base64
import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from app.models.asset import Asset
from app.services.assets import decrypt_asset


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login(client: TestClient) -> None:
    page = client.get("/admin/login")
    token = LOGIN_CSRF_PATTERN.search(page.text).group(1)
    response = client.post("/admin/login", data={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def test_h01_uploads_asset_from_person_page(client: TestClient) -> None:
    _login(client)
    created = client.post("/admin/people", data={"display_name": "Asset Person", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    person_id = created.headers["location"].rsplit("/", 1)[1]
    plaintext = b"hello.txt secret payload"
    response = client.post(
        f"/admin/people/{person_id}/assets",
        data={"display_name": "hello.txt", "csrf_token": _csrf(client)},
        files={"file": ("hello.txt", plaintext, "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get(f"/admin/people/{person_id}")
    assert "hello.txt" in page.text
    assert "加密 Vault" in page.text


def test_h02_vault_contains_ciphertext_not_plaintext(client: TestClient) -> None:
    _login(client)
    created = client.post("/admin/people", data={"display_name": "Vault Person", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    person_id = created.headers["location"].rsplit("/", 1)[1]
    plaintext = b"unique plaintext marker 7f4d"
    client.post(f"/admin/people/{person_id}/assets", data={"csrf_token": _csrf(client)}, files={"file": ("payload.bin", plaintext, "application/octet-stream")}, follow_redirects=False)
    with client.app.state.session_factory() as db:
        asset = db.scalar(select(Asset).where(Asset.person_id == person_id))
        assert asset is not None
        ciphertext = (client.app.state.settings.vault_path / asset.ciphertext_path).read_bytes()
        assert plaintext not in ciphertext
        assert ciphertext != plaintext
        assert decrypt_asset(asset, client.app.state.settings) == plaintext


def test_h03_database_stores_wrapped_dek_only(client: TestClient) -> None:
    _login(client)
    created = client.post("/admin/people", data={"display_name": "DEK Person", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    person_id = created.headers["location"].rsplit("/", 1)[1]
    client.post(f"/admin/people/{person_id}/assets", data={"csrf_token": _csrf(client)}, files={"file": ("payload.bin", b"encrypted", "application/octet-stream")}, follow_redirects=False)
    columns = {column["name"] for column in inspect(client.app.state.db_engine).get_columns("assets")}
    assert "wrapped_dek" in columns
    assert "dek" not in columns
    assert "plaintext" not in columns
    with client.app.state.session_factory() as db:
        asset = db.scalar(select(Asset).where(Asset.person_id == person_id))
        assert asset is not None
        assert asset.wrapped_dek != b"encrypted"
        assert len(asset.wrapped_dek) > 32
