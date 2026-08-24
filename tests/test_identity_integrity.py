"""D-series Identity Integrity acceptance tests."""

from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from app.models.identity import Question
from app.models.integrity import IdentityCluster, IdentityIntegritySnapshot, IdentityPairMetric
from app.models.verification import VerificationAttempt


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login(client: TestClient) -> None:
    login_page = client.get("/admin/login")
    token_match = LOGIN_CSRF_PATTERN.search(login_page.text)
    assert token_match
    response = client.post(
        "/admin/login",
        data={
            "username": "admin",
            "password": PASSWORD,
            "totp": pyotp.TOTP(TOTP_SECRET).now(),
            "csrf_token": token_match.group(1),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def _create_person(client: TestClient, name: str) -> str:
    response = client.post(
        "/admin/people",
        data={"display_name": name, "status": "active", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[1]


def _create_question(client: TestClient, text: str) -> str:
    response = client.post(
        "/admin/questions",
        data={
            "text": text,
            "privacy_level": "L1_RELATION",
            "answer_scale": "five_point",
            "weight": "1.0",
            "facet_tag": "integrity",
            "active": "on",
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        question = db.scalar(select(Question).where(Question.text_ciphertext.is_not(None)).order_by(Question.created_at.desc()))
        assert question is not None
        return question.id


def _save_trait(client: TestClient, person_id: str, question_id: str, value: float, confidence: float = 1.0) -> None:
    response = client.post(
        f"/admin/people/{person_id}/traits",
        data={
            f"value_{question_id}": str(value),
            f"confidence_{question_id}": str(confidence),
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def _current_snapshot_and_metric(
    client: TestClient,
    *,
    person_a_id: str | None = None,
    person_b_id: str | None = None,
    risk: str | None = None,
):
    with client.app.state.session_factory() as db:
        snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
        assert snapshot is not None
        query = select(IdentityPairMetric).where(IdentityPairMetric.snapshot_id == snapshot.id)
        if person_a_id and person_b_id:
            query = query.where(
                ((IdentityPairMetric.person_a_id == person_a_id) & (IdentityPairMetric.person_b_id == person_b_id))
                | ((IdentityPairMetric.person_a_id == person_b_id) & (IdentityPairMetric.person_b_id == person_a_id))
            )
        if risk:
            query = query.where(IdentityPairMetric.risk == risk)
        metric = db.scalar(query.order_by(IdentityPairMetric.id).limit(1))
        return snapshot, metric


def test_d01_identical_people_are_blocking_and_dashboard_exposes_metrics(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D01 人物 A")
    person_b = _create_person(client, "D01 人物 B")
    question = _create_question(client, "D01 共同经历是否相同？")
    _save_trait(client, person_a, question, 1.0)
    _save_trait(client, person_b, question, 1.0)

    snapshot, metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert snapshot.status == "blocking"
    assert snapshot.blocking_pair_count == 1
    assert metric is not None
    assert metric.risk == "blocking"
    assert metric.strong_discriminator_count == 0
    assert metric.common_question_count == 1
    assert metric.theoretical_max_score_separation == 0.0
    dashboard = client.get("/admin/identity-integrity")
    assert dashboard.status_code == 200
    assert "D01 人物 A" in dashboard.text
    assert "D01 人物 B" in dashboard.text
    assert "BLOCKING" in dashboard.text


def test_d02_pair_detail_explains_confusion_and_question_values(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D02 人物 A")
    person_b = _create_person(client, "D02 人物 B")
    question = _create_question(client, "D02 记忆是否相同？")
    _save_trait(client, person_a, question, 1.0)
    _save_trait(client, person_b, question, 1.0)
    _, metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert metric is not None

    detail = client.get(f"/admin/identity-integrity/pairs/{metric.id}")
    assert detail.status_code == 200
    assert "为什么冲突" in detail.text
    assert "没有满足隐私级别" in detail.text
    assert "D02 记忆是否相同？" in detail.text
    assert "BLOCKING" in detail.text
    assert "A value" in detail.text and "B value" in detail.text


def test_d03_wizard_fills_missing_trait_and_clears_pair(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D03 人物 A")
    person_b = _create_person(client, "D03 人物 B")
    question = _create_question(client, "D03 是否在同一地点工作？")
    _save_trait(client, person_a, question, 1.0)
    _, metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert metric is not None

    wizard = client.get("/admin/identity-integrity/wizard")
    assert wizard.status_code == 200
    assert "缺失 Trait" in wizard.text
    response = client.post(
        "/admin/identity-integrity/wizard/traits",
        data={
            "pair_id": metric.id,
            "question_id": question,
            "a_value": "1.0",
            "a_confidence": "1.0",
            "b_value": "-1.0",
            "b_confidence": "1.0",
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    snapshot, current_metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert snapshot.status == "pass"
    assert current_metric is not None and current_metric.risk == "pass"
    assert "暂无需要解决的 Pair" in client.get("/admin/identity-integrity/wizard").text


def test_d04_wizard_creates_discriminator_question(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D04 人物 A")
    person_b = _create_person(client, "D04 人物 B")
    _, metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert metric is not None
    wizard = client.get(f"/admin/identity-integrity/wizard?pair_id={metric.id}")
    assert "保存前预览" in wizard.text
    assert "预计增加" in wizard.text
    assert "Cluster Split Utility" in wizard.text
    response = client.post(
        "/admin/identity-integrity/wizard/question",
        data={
            "pair_id": metric.id,
            "text": "D04 新建的区分问题？",
            "privacy_level": "L2_PRIVATE",
            "facet_tag": "d04",
            "a_value": "-1.0",
            "b_value": "1.0",
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    snapshot, pair = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert snapshot.status == "pass"
    assert pair is not None and pair.risk == "pass"
    assert "D04 新建的区分问题？" in client.get("/admin/questions").text


def test_d05_same_answer_keeps_blocking_and_wizard_says_continue(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D05 人物 A")
    person_b = _create_person(client, "D05 人物 B")
    _, metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert metric is not None
    response = client.post(
        "/admin/identity-integrity/wizard/question",
        data={
            "pair_id": metric.id,
            "text": "D05 没有区分度的问题？",
            "privacy_level": "L1_RELATION",
            "facet_tag": "d05",
            "a_value": "1.0",
            "b_value": "1.0",
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    snapshot, pair = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert snapshot.status == "blocking"
    assert pair is not None and pair.risk == "blocking"
    wizard = client.get("/admin/identity-integrity/wizard")
    assert "仍需继续" in wizard.text


def test_d06_wizard_moves_to_another_risk_pair_after_resolution(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D06 人物 A")
    person_b = _create_person(client, "D06 人物 B")
    person_c = _create_person(client, "D06 人物 C")
    _, first_metric = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert first_metric is not None
    response = client.post(
        "/admin/identity-integrity/wizard/question",
        data={
            "pair_id": first_metric.id,
            "text": "D06 只区分首个 Pair 的问题？",
            "privacy_level": "L1_RELATION",
            "facet_tag": "d06",
            "a_value": "-1.0",
            "b_value": "1.0",
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    snapshot, resolved = _current_snapshot_and_metric(client, person_a_id=person_a, person_b_id=person_b)
    assert snapshot.status == "blocking"
    assert resolved is not None and resolved.risk == "pass"
    next_wizard = client.get("/admin/identity-integrity/wizard")
    assert next_wizard.status_code == 200
    _, next_metric = _current_snapshot_and_metric(client, risk="blocking")
    assert next_metric is not None
    assert next_metric.id != resolved.id
    selected = re.search(
        r'<p class="muted">([0-9a-f-]{36}) / ([0-9a-f-]{36}) · BLOCKING',
        next_wizard.text,
    )
    assert selected is not None
    assert set(selected.groups()) != {resolved.person_a_id, resolved.person_b_id}


def test_d07_cluster_contains_members_and_split_utility(client: TestClient) -> None:
    _login(client)
    names = ["D07 人物 A", "D07 人物 B", "D07 人物 C"]
    people = [_create_person(client, name) for name in names]
    snapshot, _ = _current_snapshot_and_metric(client)
    assert snapshot.blocking_pair_count == 3
    with client.app.state.session_factory() as db:
        cluster = db.scalar(select(IdentityCluster).where(IdentityCluster.snapshot_id == snapshot.id))
        assert cluster is not None
        cluster_id = cluster.id
    detail = client.get(f"/admin/identity-integrity/clusters/{cluster_id}")
    assert detail.status_code == 200
    assert "Cluster Split Utility" in detail.text
    assert all(name in detail.text for name in names)
    assert "worst pair" in detail.text
    assert all(person_id in detail.text for person_id in people)


def test_d08_simulator_exposes_exact_and_human_noise_without_grant(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D08 人物 A")
    person_b = _create_person(client, "D08 人物 B")
    question = _create_question(client, "D08 模拟问题？")
    _save_trait(client, person_a, question, -1.0)
    _save_trait(client, person_b, question, 1.0)
    exact = client.post(
        "/admin/simulator",
        data={"target_person_id": person_a, "profile": "EXACT", "seed": "42", "csrf_token": _csrf(client)},
    )
    assert exact.status_code == 200
    assert "algorithm=identity-engine-v1" in exact.text
    assert "noise=exact-v1" in exact.text
    assert "不创建 VerificationAttempt 或 Grant" in exact.text
    table_names = set(inspect(client.app.state.db_engine).get_table_names())
    assert "grants" not in table_names
    with client.app.state.session_factory() as db:
        assert db.query(VerificationAttempt).count() == 0
    noisy = client.post(
        "/admin/simulator",
        data={"target_person_id": person_a, "profile": "HUMAN_NOISE", "seed": "42", "csrf_token": _csrf(client)},
    )
    assert noisy.status_code == 200
    assert "noise=human-noise-v1" in noisy.text
    assert "回答轨迹" in noisy.text
    assert "UNKNOWN" in noisy.text


def test_d09_person_detail_shows_closest_person_and_wizard_entry(client: TestClient) -> None:
    _login(client)
    person_a = _create_person(client, "D09 人物 A")
    _create_person(client, "D09 人物 B")
    detail = client.get(f"/admin/people/{person_a}")
    assert detail.status_code == 200
    assert "Identity model incomplete" in detail.text
    assert "当前最相近人物" in detail.text
    assert "/admin/identity-integrity/wizard" in detail.text


def test_identity_integrity_full_recompute_persists_full_snapshot(client: TestClient) -> None:
    _login(client)
    _create_person(client, "Full Recompute A")
    _create_person(client, "Full Recompute B")
    response = client.post("/admin/identity-integrity/recompute", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    with client.app.state.session_factory() as db:
        snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
        assert snapshot is not None
        assert snapshot.mode == "full"
        assert snapshot.finished_at is not None
