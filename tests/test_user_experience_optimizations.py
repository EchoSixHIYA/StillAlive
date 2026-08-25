"""Regression tests for the report-driven administrator and public UX changes."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.audit import AuditEvent
from app.models.asset import Asset
from app.models.delivery import DeliveryProfile
from app.models.discovery import DiscoverySession
from app.models.identity import Person, Question, TraitAnswer
from app.models.grant import DownloadGrant
from app.models.verification import VerificationChallenge
from app.services.grants import create_grant


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
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def _create_person(client: TestClient, name: str) -> str:
    response = client.post("/admin/people", data={"display_name": name, "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[1]


def test_setup_wizard_exposes_reported_first_use_sequence(client: TestClient) -> None:
    _login(client)
    page = client.get("/admin/setup")
    assert page.status_code == 200
    assert "首次配置向导" in page.text
    sequence = ["建立人物", "建立识别问题", "补齐识别特征", "配置专属验证", "上传遗产内容", "用朋友视角试跑", "保存 Recovery Key", "通过身份完整性检查", "创建离线封存包"]
    positions = [page.text.index(label) for label in sequence]
    assert positions == sorted(positions)
    assert "启动后即可交付" in page.text


def test_person_and_asset_labels_can_be_edited_without_replacing_ciphertext(client: TestClient) -> None:
    _login(client)
    person_id = _create_person(client, "待修改人物")
    updated = client.post(
        f"/admin/people/{person_id}",
        data={"display_name": "已修改人物", "status": "active", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert updated.status_code == 303
    assert "已修改人物" in client.get(f"/admin/people/{person_id}").text

    uploaded = client.post(
        f"/admin/people/{person_id}/assets",
        data={"display_name": "原始名称.txt", "csrf_token": _csrf(client)},
        files={"file": ("payload.txt", b"private content", "text/plain")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    with client.app.state.session_factory() as db:
        asset = db.scalar(select(Asset).where(Asset.person_id == person_id))
    assert asset is not None
    renamed = client.post(
        f"/admin/people/{person_id}/assets/{asset.id}/rename",
        data={"display_name": "新名称.txt", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert renamed.status_code == 303
    detail = client.get(f"/admin/people/{person_id}")
    assert "新名称.txt" in detail.text
    assert "原始名称.txt" not in detail.text


def test_identity_integrity_todo_uses_names_and_question_text(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "待区分人物甲")
    person_b = _create_person(client, "待区分人物乙")
    created = client.post(
        "/admin/questions",
        data={"text": "哪一个答案应该补齐？", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "todo", "active": "on", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).where(Question.facet_tag == "todo"))
    assert question is not None
    saved = client.post(
        f"/admin/people/{person_a}/traits",
        data={f"value_{question.id}": "1.0", f"confidence_{question.id}": "1.0", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    dashboard = client.get("/admin/identity-integrity")
    assert "待区分人物甲" in dashboard.text
    assert "待区分人物乙" in dashboard.text
    assert "哪一个答案应该补齐？" in dashboard.text
    assert "下一步待办" in dashboard.text


def test_public_page_explains_immediate_delivery_and_flow_progress(client: TestClient) -> None:
    _login(client)
    _create_person(client, "前台人物")
    client.post("/admin/questions", data={"text": "前台问题？", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "public", "active": "on", "csrf_token": _csrf(client)}, follow_redirects=False)
    home = client.get("/")
    assert "服务启动后即可交付" in home.text
    assert "心跳触发" in home.text
    started = client.post("/start", follow_redirects=False)
    play = client.get(started.headers["location"])
    assert "flow-progress" in play.text
    assert "交付" in play.text


def test_release_page_turns_failed_gates_into_actions(client: TestClient) -> None:
    _login(client)
    page = client.get("/admin/releases")
    assert page.status_code == 200
    assert "封存前检查" in page.text
    assert "Identity Integrity" in page.text
    assert "FAIL" in page.text
    assert "/admin/identity-integrity" in page.text


def test_normal_trait_mode_maps_plain_language_to_identity_values(client: TestClient) -> None:
    _login(client)
    person_id = _create_person(client, "普通答案人物")
    client.post("/admin/questions", data={"text": "普通模式问题？", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "plain", "active": "on", "csrf_token": _csrf(client)}, follow_redirects=False)
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).where(Question.facet_tag == "plain"))
    assert question is not None
    response = client.post(
        f"/admin/people/{person_id}/traits",
        data={f"answer_choice_{question.id}": "probably_no", f"confidence_level_{question.id}": "likely", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    detail = client.get(f"/admin/people/{person_id}")
    assert "普通模式：用自然语言选择" in detail.text
    assert "高级设置（数字字段）" in detail.text
    with client.app.state.session_factory() as db:
        answer = db.get(TraitAnswer, (person_id, question.id))
        assert answer is not None
        assert answer.value == -0.5
        assert answer.confidence == 0.75


def test_delivery_profile_and_phone_preview_are_personalized_without_a_session(client: TestClient) -> None:
    _login(client)
    person_id = _create_person(client, "预览人物")
    response = client.post(
        f"/admin/people/{person_id}/delivery-profile",
        data={"theme": "warm", "content_type": "photos", "cover_title": "给你的一封信", "opening": "愿你看到这里时，已经平安。", "signature": "你的朋友", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    preview = client.get(f"/admin/people/{person_id}/preview")
    assert preview.status_code == 200
    assert "给你的一封信" in preview.text
    assert "愿你看到这里时，已经平安。" in preview.text
    assert "朋友手机视角" in preview.text
    assert "不会创建正式会话" in preview.text
    with client.app.state.session_factory() as db:
        profile = db.scalar(select(DeliveryProfile).where(DeliveryProfile.person_id == person_id))
        assert profile is not None
        assert "给你的一封信".encode("utf-8") not in (profile.cover_title_ciphertext or b"")
        assert db.scalar(select(DiscoverySession)) is None


def test_revoke_restore_and_permanent_delete_have_distinct_safe_semantics(client: TestClient) -> None:
    _login(client)
    person_id = _create_person(client, "生命周期人物")
    upload = client.post(f"/admin/people/{person_id}/assets", data={"display_name": "要删除的内容.txt", "csrf_token": _csrf(client)}, files={"file": ("payload.txt", b"private lifecycle payload", "text/plain")}, follow_redirects=False)
    assert upload.status_code == 303
    challenge_response = client.post(f"/admin/people/{person_id}/challenges", data={"prompt": "生命周期验证？", "answers": "答案", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert challenge_response.status_code == 303
    with client.app.state.session_factory() as db:
        person = db.get(Person, person_id)
        asset = db.scalar(select(Asset).where(Asset.person_id == person_id))
        challenge = db.scalar(select(VerificationChallenge).where(VerificationChallenge.person_id == person_id))
        assert person is not None and asset is not None and challenge is not None
        session = DiscoverySession(status="verified", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), confirmed_person_id=person_id)
        db.add(session)
        db.flush()
        create_grant(db, session, client.app.state.settings, asset_id=asset.id)
        db.commit()

    revoke = client.post(f"/admin/people/{person_id}/revoke-delivery", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert revoke.status_code == 303
    with client.app.state.session_factory() as db:
        person = db.get(Person, person_id)
        session = db.scalar(select(DiscoverySession).where(DiscoverySession.confirmed_person_id == person_id))
        grant = db.scalar(select(DownloadGrant).where(DownloadGrant.person_id == person_id))
        assert person is not None and person.delivery_enabled is False
        assert session is not None and session.status == "expired"
        assert grant is not None and grant.revoked_at is not None
    restore = client.post(f"/admin/people/{person_id}/restore-delivery", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert restore.status_code == 303
    with client.app.state.session_factory() as db:
        assert db.get(Person, person_id).delivery_enabled is True

    blocked = client.post(f"/admin/people/{person_id}/delete", data={"confirm_text": "删除", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert blocked.status_code == 400
    deleted = client.post(f"/admin/people/{person_id}/delete", data={"confirm_text": "永久删除", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert deleted.status_code == 303
    with client.app.state.session_factory() as db:
        assert db.get(Person, person_id) is None
        assert db.scalar(select(Asset).where(Asset.person_id == person_id)) is None
        assert db.scalar(select(VerificationChallenge).where(VerificationChallenge.person_id == person_id)) is None
        audit = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "person.permanently_deleted", AuditEvent.target_id == person_id))
        assert audit is not None
