"""Regression tests for the report-driven administrator and public UX changes."""

from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.asset import Asset
from app.models.identity import Question


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
