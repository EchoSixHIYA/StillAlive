"""G-series Verification acceptance tests."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.audit import AuditEvent
from app.models.discovery import DiscoverySession
from app.models.identity import Question
from app.models.verification import VerificationAnswerDigest, VerificationAttempt, VerificationChallenge
from app.services.verification import normalize_answer


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
    response = client.post(
        "/admin/questions",
        data={"text": text, "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "verification", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).order_by(Question.created_at.desc()).limit(1))
        assert question is not None
        return question.id


def _trait(client: TestClient, person_id: str, question_id: str, value: float) -> None:
    response = client.post(f"/admin/people/{person_id}/traits", data={f"value_{question_id}": str(value), f"confidence_{question_id}": "1.0", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303


def _setup(client: TestClient) -> tuple[str, str]:
    _login(client)
    target = _person(client, "Verification Person A")
    _person(client, "Verification Person B")
    questions = [_question(client, f"Verification discovery {index}?") for index in range(3)]
    for question_id in questions:
        _trait(client, target, question_id, 1.0)
    response = client.post(
        f"/admin/people/{target}/challenges",
        data={"prompt": "我们第一次一起玩的游戏是什么？", "answers": "秘密花园\nSecret Garden", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        challenge = db.scalar(select(VerificationChallenge).where(VerificationChallenge.person_id == target))
        assert challenge is not None
        return target, challenge.id


def _identify_target(client: TestClient) -> str:
    payload = client.post("/api/public/sessions", json={}).json()
    for _ in range(3):
        payload = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": payload["question"]["id"], "answer": "yes"}).json()
    assert payload["state"] == "GUESS"
    accepted = client.post(f"/api/public/sessions/{payload['session_id']}/guess", json={"accepted": True})
    assert accepted.json()["state"] == "VERIFICATION"
    return payload["session_id"]


def test_g01_admin_challenge_shows_prompt_and_count_but_not_answer(client: TestClient) -> None:
    target, _ = _setup(client)
    page = client.get(f"/admin/people/{target}")
    assert page.status_code == 200
    assert "我们第一次一起玩的游戏是什么？" in page.text
    assert "已配置 2 个可接受答案" in page.text
    assert "秘密花园" not in page.text
    assert "Secret Garden" not in page.text
    with client.app.state.session_factory() as db:
        digest = db.scalar(select(VerificationAnswerDigest))
        assert digest is not None
        assert digest.answer_hmac != "秘密花园".encode("utf-8")


def test_g02_correct_answer_verifies_session(client: TestClient) -> None:
    target, challenge_id = _setup(client)
    session_id = _identify_target(client)
    challenge = client.get(f"/api/public/sessions/{session_id}/challenge")
    assert challenge.status_code == 200
    assert challenge.json()["challenge"]["id"] == challenge_id
    assert challenge.json()["challenge"]["prompt"] == "我们第一次一起玩的游戏是什么？"
    assert "秘密花园" not in challenge.text
    verified = client.post(f"/api/public/sessions/{session_id}/verify", json={"challenge_id": challenge_id, "answer": "  秘密花园。 "})
    assert verified.status_code == 200
    assert verified.json()["state"] == "VERIFIED"
    assert client.get(f"/api/public/sessions/{session_id}").json()["state"] == "VERIFIED"
    with client.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        assert session.confirmed_person_id == target


def test_g03_wrong_answer_does_not_verify_or_leak_answer(client: TestClient) -> None:
    _setup(client)
    session_id = _identify_target(client)
    challenge = client.get(f"/api/public/sessions/{session_id}/challenge").json()["challenge"]
    wrong = client.post(f"/api/public/sessions/{session_id}/verify", json={"challenge_id": challenge["id"], "answer": "完全错误"})
    assert wrong.status_code == 200
    assert wrong.json()["state"] == "VERIFICATION"
    assert "秘密花园" not in wrong.text
    with client.app.state.session_factory() as db:
        attempt = db.scalar(select(VerificationAttempt).where(VerificationAttempt.session_id == session_id))
        failure = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "verification.failed"))
    assert attempt is not None and attempt.success is False
    assert failure is not None
    assert "完全错误" not in failure.metadata_json
    assert "秘密花园" not in failure.metadata_json


def test_g04_five_failed_answers_lock_session(client: TestClient) -> None:
    _setup(client)
    session_id = _identify_target(client)
    challenge = client.get(f"/api/public/sessions/{session_id}/challenge").json()["challenge"]
    for attempt_number in range(5):
        with client.app.state.session_factory() as db:
            attempts = db.scalars(select(VerificationAttempt).where(VerificationAttempt.session_id == session_id)).all()
            for attempt in attempts:
                attempt.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            db.commit()
        response = client.post(f"/api/public/sessions/{session_id}/verify", json={"challenge_id": challenge["id"], "answer": f"wrong-{attempt_number}"})
        assert response.status_code == 200
    assert response.json()["state"] == "LOCKED"
    repeat = client.post(f"/api/public/sessions/{session_id}/verify", json={"challenge_id": challenge["id"], "answer": "Secret Garden"})
    assert repeat.status_code == 409
    assert normalize_answer("  Hello,  WORLD! ") == "hello, world"
