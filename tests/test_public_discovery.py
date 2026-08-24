"""E-series Public Discovery acceptance tests."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.discovery import DiscoverySession
from app.models.identity import Question


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


def _create_person(client: TestClient, name: str) -> str:
    response = client.post("/admin/people", data={"display_name": name, "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[1]


def _create_question(client: TestClient, text: str) -> str:
    response = client.post(
        "/admin/questions",
        data={"text": text, "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "public", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).order_by(Question.created_at.desc()).limit(1))
        assert question is not None
        return question.id


def _save_trait(client: TestClient, person_id: str, question_id: str, value: float) -> None:
    response = client.post(
        f"/admin/people/{person_id}/traits",
        data={f"value_{question_id}": str(value), f"confidence_{question_id}": "1.0", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _fixture(client: TestClient, *, people_count: int = 2, question_count: int = 3) -> tuple[list[str], list[str]]:
    _login(client)
    people = [_create_person(client, f"Public Person {index}") for index in range(people_count)]
    questions = [_create_question(client, f"Public question {index}?") for index in range(question_count)]
    for person_index, person_id in enumerate(people):
        for question_id in questions:
            _save_trait(client, person_id, question_id, 1.0 if person_index == 0 else -1.0)
    return people, questions


def test_e01_home_starts_public_session_without_release_or_lifecycle_gate(client: TestClient) -> None:
    _login(client)
    _create_person(client, "Public Person A")
    _create_question(client, "E01 question?")
    home = client.get("/")
    assert home.status_code == 200
    assert "开始识别" in home.text
    assert "Heartbeat" not in home.text
    response = client.post("/start", follow_redirects=False)
    assert response.status_code == 303
    play = client.get(response.headers["location"])
    assert play.status_code == 200
    assert "回答一个问题" in play.text
    assert "Public Person A" not in play.text


def test_e02_public_answers_return_one_new_question_at_a_time(client: TestClient) -> None:
    people, _ = _fixture(client)
    response = client.post("/api/public/sessions", json={})
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "QUESTION"
    seen_questions: set[str] = set()
    for _ in range(3):
        question = payload["question"]
        seen_questions.add(question["id"])
        assert set(payload) == {"session_id", "state", "question"}
        response = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": question["id"], "answer": "yes"})
        assert response.status_code == 200
        payload = response.json()
    assert len(seen_questions) == 3
    assert people[1] not in response.text


def test_e03_correct_answers_show_only_single_guess(client: TestClient) -> None:
    people, _ = _fixture(client)
    payload = client.post("/api/public/sessions", json={}).json()
    for _ in range(3):
        question_id = payload["question"]["id"]
        payload = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": question_id, "answer": "yes"}).json()
    assert payload["state"] == "GUESS"
    assert payload["guess"]["display_name"] == "Public Person 0"
    assert people[1] not in str(payload)
    page = client.get(f"/play/{payload['session_id']}")
    assert "我猜你是：Public Person 0" in page.text
    assert "top2" not in page.text.lower()
    assert "%" not in page.text


def test_e04_rejecting_guess_continues_without_immediate_verification(client: TestClient) -> None:
    _login(client)
    people = [_create_person(client, f"Reject Person {index}") for index in range(3)]
    questions = [_create_question(client, f"Reject question {index}?") for index in range(6)]
    for person_index, person_id in enumerate(people):
        for question_id in questions:
            _save_trait(client, person_id, question_id, 1.0 if person_index == 0 else -1.0)
    payload = client.post("/api/public/sessions", json={}).json()
    asked_questions: set[str] = set()
    for _ in range(3):
        question_id = payload["question"]["id"]
        asked_questions.add(question_id)
        payload = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": question_id, "answer": "yes"}).json()
    assert payload["state"] == "GUESS"
    rejected = client.post(f"/api/public/sessions/{payload['session_id']}/guess", json={"accepted": False})
    assert rejected.status_code == 200
    assert rejected.json()["state"] == "QUESTION"
    assert rejected.json()["question"]["id"] not in asked_questions
    assert "VERIFICATION" not in rejected.text


def test_e05_identical_people_end_in_unable_to_identify_not_a_forced_guess(client: TestClient) -> None:
    _login(client)
    people = [_create_person(client, f"Identical Person {index}") for index in range(2)]
    questions = [_create_question(client, f"Identical question {index}?") for index in range(3)]
    for person_id in people:
        for question_id in questions:
            _save_trait(client, person_id, question_id, 1.0)
    payload = client.post("/api/public/sessions", json={}).json()
    for _ in range(3):
        payload = client.post(f"/api/public/sessions/{payload['session_id']}/answers", json={"question_id": payload["question"]["id"], "answer": "yes"}).json()
    assert payload["state"] == "UNABLE_TO_IDENTIFY"
    page = client.get(f"/play/{payload['session_id']}")
    assert "暂时无法确定身份" in page.text
    assert "Identical Person" not in page.text


def test_public_session_expiry_is_server_enforced(client: TestClient) -> None:
    _login(client)
    _create_person(client, "Expiry Person")
    response = client.post("/api/public/sessions", json={})
    assert response.status_code == 201
    session_id = response.json()["session_id"]
    with client.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        assert session is not None
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    expired = client.get(f"/api/public/sessions/{session_id}")
    assert expired.status_code == 200
    assert expired.json()["state"] == "EXPIRED"
