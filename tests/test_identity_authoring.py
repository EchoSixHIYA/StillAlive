"""C-series Person, Question, and TraitAnswer acceptance tests."""

from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.audit import AuditEvent
from app.models.identity import Person, Question, TraitAnswer
from app.services.metadata import decrypt_trait_note


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login(client: TestClient) -> None:
    login_page = client.get("/admin/login")
    token = LOGIN_CSRF_PATTERN.search(login_page.text).group(1)
    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    return client.cookies.get("still_alive_admin_csrf")


def test_c01_create_person_by_web(client: TestClient) -> None:
    _login(client)
    response = client.post("/admin/people", data={"display_name": "测试角色A", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/admin/people/")
    assert "测试角色A" not in location

    detail = client.get(location)
    assert detail.status_code == 200
    assert "测试角色A" in detail.text
    assert "Identity model incomplete" in detail.text
    listing = client.get("/admin/people")
    assert "测试角色A" in listing.text

    with client.app.state.session_factory() as db:
        person = db.scalar(select(Person))
    assert person is not None
    assert "测试角色A".encode("utf-8") not in person.display_name_ciphertext
    assert person.slug_internal not in location


def test_c02_create_and_edit_question_by_web(client: TestClient) -> None:
    _login(client)
    question_text = "我们在线下见过吗？"
    response = client.post(
        "/admin/questions",
        data={"text": question_text, "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.5", "facet_tag": "offline", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    listing = client.get("/admin/questions")
    assert listing.status_code == 200
    assert question_text in listing.text
    assert "L1_RELATION" in listing.text
    assert "offline" in listing.text

    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question))
    assert question is not None
    assert question_text.encode("utf-8") not in question.text_ciphertext

    edit = client.get(f"/admin/questions/{question.id}/edit")
    assert edit.status_code == 200
    assert question_text in edit.text
    updated = client.post(
        f"/admin/questions/{question.id}",
        data={"text": "我们第一次认识是否因为工作？", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "2.0", "facet_tag": "work", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert updated.status_code == 303
    assert "我们第一次认识是否因为工作？" in client.get("/admin/questions").text


def test_c03_edit_trait_answers_and_encrypt_source_note(client: TestClient) -> None:
    _login(client)
    person_response = client.post("/admin/people", data={"display_name": "测试角色A", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    person_id = person_response.headers["location"].rsplit("/", 1)[1]
    client.post("/admin/questions", data={"text": "我们在线下见过吗？", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "offline", "active": "on", "csrf_token": _csrf(client)}, follow_redirects=False)

    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question))
    assert question is not None
    response = client.post(
        f"/admin/people/{person_id}/traits",
        data={f"value_{question.id}": "1.0", f"confidence_{question.id}": "0.9", f"source_note_{question.id}": "仅管理员可见备注", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    detail = client.get(f"/admin/people/{person_id}")
    assert "1.0" in detail.text
    assert "仅管理员可见备注" in detail.text

    with client.app.state.session_factory() as db:
        answer = db.get(TraitAnswer, (person_id, question.id))
        stale_events = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "identity_integrity.stale")).all()
    assert answer is not None
    assert answer.value == 1.0
    assert answer.confidence == 0.9
    assert answer.source_note_ciphertext != "仅管理员可见备注".encode("utf-8")
    assert answer.source_note_nonce
    assert decrypt_trait_note(answer.source_note_ciphertext, answer.source_note_nonce, client.app.state.settings.master_key_bytes) == "仅管理员可见备注"
    assert stale_events


def test_c04_l4_cannot_be_active_discovery_question(client: TestClient) -> None:
    _login(client)
    response = client.post(
        "/admin/questions",
        data={"text": "Verification-only question", "privacy_level": "L4_VERIFICATION_ONLY", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "memory", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 409
    assert "L4_VERIFICATION_ONLY" in response.text

    inactive = client.post(
        "/admin/questions",
        data={"text": "Verification-only question", "privacy_level": "L4_VERIFICATION_ONLY", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "memory", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert inactive.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question))
    assert question is not None
    assert question.privacy_level == "L4_VERIFICATION_ONLY"
    assert question.active is False

