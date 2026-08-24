"""I-series DownloadGrant and encrypted download acceptance tests."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.asset import Asset
from app.models.grant import DownloadGrant
from app.models.identity import Question
from app.models.verification import VerificationChallenge


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


def _person(client: TestClient, name: str) -> str:
    response = client.post("/admin/people", data={"display_name": name, "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[1]


def _question(client: TestClient, text: str) -> str:
    response = client.post("/admin/questions", data={"text": text, "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "grant", "active": "on", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).order_by(Question.created_at.desc()).limit(1))
        assert question is not None
        return question.id


def _trait(client: TestClient, person_id: str, question_id: str, value: float) -> None:
    response = client.post(f"/admin/people/{person_id}/traits", data={f"value_{question_id}": str(value), f"confidence_{question_id}": "1.0", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303


def _setup(client: TestClient) -> tuple[str, str, str]:
    _login(client)
    target = _person(client, "Grant Person A")
    other = _person(client, "Grant Person B")
    questions = [_question(client, f"Grant discovery {index}?") for index in range(3)]
    for question_id in questions:
        _trait(client, target, question_id, 1.0)
    challenge_response = client.post(f"/admin/people/{target}/challenges", data={"prompt": "Grant verification?", "answers": "download secret", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert challenge_response.status_code == 303
    asset_response = client.post(f"/admin/people/{target}/assets", data={"display_name": "hello.txt", "csrf_token": _csrf(client)}, files={"file": ("hello.txt", b"download payload", "text/plain")}, follow_redirects=False)
    assert asset_response.status_code == 303
    other_asset_response = client.post(f"/admin/people/{other}/assets", data={"display_name": "other.txt", "csrf_token": _csrf(client)}, files={"file": ("other.txt", b"other payload", "text/plain")}, follow_redirects=False)
    assert other_asset_response.status_code == 303
    with client.app.state.session_factory() as db:
        asset = db.scalar(select(Asset).where(Asset.person_id == target))
        other_asset = db.scalar(select(Asset).where(Asset.person_id == other))
        challenge = db.scalar(select(VerificationChallenge).where(VerificationChallenge.person_id == target))
        assert asset is not None and other_asset is not None and challenge is not None
        return target, asset.id, other_asset.id


def _verified_session(client: TestClient, challenge_answer: str = "download secret") -> str:
    payload = client.post("/api/public/sessions", json={}).json()
    for _ in range(3):
        payload = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": payload["question"]["id"], "answer": "yes"}).json()
    assert payload["state"] == "GUESS"
    accepted = client.post(f"/api/public/sessions/{payload['session_id']}/guess", json={"accepted": True}).json()
    assert accepted["state"] == "VERIFICATION"
    challenge = client.get(f"/api/public/sessions/{payload['session_id']}/challenge").json()["challenge"]
    verified = client.post(f"/api/public/sessions/{payload['session_id']}/verify", json={"challenge_id": challenge["id"], "answer": challenge_answer})
    assert verified.status_code == 200 and verified.json()["state"] == "VERIFIED"
    return payload["session_id"]


def test_i01_verified_session_gets_single_use_download(client: TestClient) -> None:
    _, asset_id, _ = _setup(client)
    session_id = _verified_session(client)
    assets = client.get(f"/api/public/sessions/{session_id}/assets")
    assert assets.status_code == 200
    assert assets.json()["assets"][0]["display_name"] == "hello.txt"
    grant = client.post(f"/api/public/sessions/{session_id}/assets/{asset_id}/grant")
    assert grant.status_code == 200
    download_url = grant.json()["download_url"]
    assert "vault" not in download_url.lower()
    assert "hello.txt" not in download_url
    downloaded = client.get(download_url)
    assert downloaded.status_code == 200
    assert downloaded.content == b"download payload"
    assert "hello.txt" in downloaded.headers["content-disposition"]
    assert client.get(download_url).status_code == 410


def test_i02_unverified_session_cannot_create_or_use_grant(client: TestClient) -> None:
    _, asset_id, _ = _setup(client)
    session_id = client.post("/api/public/sessions", json={}).json()["session_id"]
    assert client.post(f"/api/public/sessions/{session_id}/assets/{asset_id}/grant").status_code == 403
    assert client.get("/download/not-a-real-token").status_code == 404


def test_i03_verified_session_cannot_grant_other_person_asset(client: TestClient) -> None:
    _, asset_id, other_asset_id = _setup(client)
    session_id = _verified_session(client)
    response = client.post(f"/api/public/sessions/{session_id}/assets/{other_asset_id}/grant")
    assert response.status_code == 404
    with client.app.state.session_factory() as db:
        assert db.scalar(select(DownloadGrant).where(DownloadGrant.asset_id == other_asset_id)) is None


def test_i05_expired_grant_cannot_download(client: TestClient) -> None:
    _, asset_id, _ = _setup(client)
    session_id = _verified_session(client)
    grant_response = client.post(f"/api/public/sessions/{session_id}/assets/{asset_id}/grant")
    url = grant_response.json()["download_url"]
    token = url.rsplit("/", 1)[1]
    with client.app.state.session_factory() as db:
        grant = db.scalar(select(DownloadGrant))
        assert grant is not None
        grant.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert client.get(f"/download/{token}").status_code == 410
