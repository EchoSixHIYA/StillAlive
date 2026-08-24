"""Identity Integrity Dashboard, Pair/Cluster explanations, Wizard, Simulator."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.models.admin import AdminUser
from app.models.identity import Person, Question, TraitAnswer
from app.models.integrity import IdentityCluster, IdentityIntegritySnapshot, IdentityPairMetric
from app.security.admin_auth import require_admin, validate_admin_csrf
from app.services.audit import record_audit
from app.services.identity.engine import IdentityEngineConfig
from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile, TraitValue
from app.services.identity.simulator import NoiseProfile, simulate
from app.services.identity_integrity import DISCOVERY_PRIVACY_LEVELS, mark_latest_stale, recompute_integrity, recompute_incremental
from app.services.metadata import decrypt_person_name, decrypt_question_text, encrypt_question_text


router = APIRouter(prefix="/admin", tags=["identity-integrity"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _csrf(request: Request) -> str:
    return request.cookies.get("still_alive_admin_csrf", "")


def _require_csrf(request: Request, token: str | None) -> None:
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")


def _latest(db):
    return db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))


def _person_names(db, ids: set[str], master_key: bytes) -> dict[str, str]:
    people = db.scalars(select(Person).where(Person.id.in_(ids))).all() if ids else []
    return {person.id: decrypt_person_name(person.display_name_ciphertext, person.display_name_nonce, master_key) for person in people}


def _metric_view(db, metric: IdentityPairMetric, master_key: bytes) -> dict[str, object]:
    names = _person_names(db, {metric.person_a_id, metric.person_b_id}, master_key)
    return {"metric": metric, "person_a_name": names.get(metric.person_a_id, metric.person_a_id), "person_b_name": names.get(metric.person_b_id, metric.person_b_id)}


def _pair_for_wizard(db, snapshot: IdentityIntegritySnapshot | None, pair_id: str | None) -> IdentityPairMetric | None:
    if snapshot is None:
        return None
    if pair_id:
        candidate = db.get(IdentityPairMetric, pair_id)
        if candidate and candidate.snapshot_id == snapshot.id and candidate.risk in {"warning", "blocking"}:
            return candidate
    candidates = db.scalars(
        select(IdentityPairMetric).where(
            IdentityPairMetric.snapshot_id == snapshot.id,
            IdentityPairMetric.risk.in_(["warning", "blocking"]),
        )
    ).all()
    return max(
        candidates,
        key=lambda metric: (
            1 if metric.risk == "blocking" else 0,
            max(metric.confusion_a_to_b, metric.confusion_b_to_a),
            metric.person_a_id,
            metric.person_b_id,
        ),
        default=None,
    )


def _trait_map(db, person_ids: set[str]) -> dict[tuple[str, str], TraitAnswer]:
    answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id.in_(person_ids))).all() if person_ids else []
    return {(answer.person_id, answer.question_id): answer for answer in answers}


@router.get("/identity-integrity", response_class=HTMLResponse)
def integrity_dashboard(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        snapshot = _latest(db)
        pair_views = []
        clusters = []
        if snapshot:
            pair_views = [_metric_view(db, metric, request.app.state.settings.master_key_bytes) for metric in db.scalars(select(IdentityPairMetric).where(IdentityPairMetric.snapshot_id == snapshot.id).order_by(IdentityPairMetric.risk.desc(), IdentityPairMetric.confusion_a_to_b.desc())).all()]
            clusters = db.scalars(select(IdentityCluster).where(IdentityCluster.snapshot_id == snapshot.id)).all()
    return templates.TemplateResponse(request=request, name="admin/integrity_dashboard.html", context={"admin": admin, "csrf_token": _csrf(request), "snapshot": snapshot, "pair_views": pair_views, "clusters": clusters})


@router.post("/identity-integrity/recompute")
def integrity_recompute(request: Request, csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        record_audit(db, actor_type="admin", event_type="identity_integrity.recompute.started", actor_id=admin.id)
        db.commit()
    snapshot = recompute_integrity(request.app.state.db_engine, request.app.state.settings, mode="full")
    with request.app.state.session_factory() as db:
        record_audit(db, actor_type="admin", event_type="identity_integrity.recompute.completed", actor_id=admin.id, metadata={"snapshot_id": snapshot.id, "status": snapshot.status})
        db.commit()
    return RedirectResponse("/admin/identity-integrity", status_code=303)


@router.get("/identity-integrity/pairs/{pair_id}", response_class=HTMLResponse)
def pair_detail(request: Request, pair_id: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        metric = db.get(IdentityPairMetric, pair_id)
        if metric is None:
            raise HTTPException(status_code=404, detail="Pair not found")
        person_ids = {metric.person_a_id, metric.person_b_id}
        names = _person_names(db, person_ids, request.app.state.settings.master_key_bytes)
        answers = _trait_map(db, person_ids)
        questions = db.scalars(select(Question).order_by(Question.weight.desc(), Question.id)).all()
        question_views = []
        for question in questions:
            a = answers.get((metric.person_a_id, question.id))
            b = answers.get((metric.person_b_id, question.id))
            text = decrypt_question_text(question.text_ciphertext, question.text_nonce, request.app.state.settings.master_key_bytes)
            question_views.append({"question": question, "text": text, "a": a, "b": b, "difference": abs((a.value if a else 0) - (b.value if b else 0)) if a and b else None})
    reasons = []
    if metric.risk == "blocking":
        reasons.append("当前风险为 BLOCKING，不能安全地把单一猜测交给后续流程。")
    if metric.strong_discriminator_count == 0:
        reasons.append("没有满足隐私级别、覆盖率、差异和 confidence 条件的 Strong Discriminator。")
    if metric.trait_similarity >= 0.999999:
        reasons.append("双方已填写 Trait 的预期答案完全相同或几乎相同。")
    if metric.confusion_a_to_b or metric.confusion_b_to_a:
        reasons.append("HUMAN_NOISE 模拟出现交叉误识别。")
    return templates.TemplateResponse(request=request, name="admin/pair_detail.html", context={"admin": admin, "csrf_token": _csrf(request), "metric": metric, "person_a_name": names.get(metric.person_a_id, metric.person_a_id), "person_b_name": names.get(metric.person_b_id, metric.person_b_id), "question_views": question_views, "reasons": reasons})


@router.get("/identity-integrity/clusters/{cluster_id}", response_class=HTMLResponse)
def cluster_detail(request: Request, cluster_id: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        cluster = db.get(IdentityCluster, cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        member_ids = set(json.loads(cluster.member_person_ids))
        names = _person_names(db, member_ids, request.app.state.settings.master_key_bytes)
        pairs = db.scalars(select(IdentityPairMetric).where(IdentityPairMetric.snapshot_id == cluster.snapshot_id, IdentityPairMetric.person_a_id.in_(member_ids), IdentityPairMetric.person_b_id.in_(member_ids))).all()
        questions = db.scalars(select(Question).where(Question.active.is_(True), Question.privacy_level.in_(DISCOVERY_PRIVACY_LEVELS))).all()
        answers = _trait_map(db, member_ids)
        split_utility = []
        for question in questions:
            groups: dict[float, int] = {}
            for person_id in member_ids:
                answer = answers.get((person_id, question.id))
                if answer:
                    groups[answer.value] = groups.get(answer.value, 0) + 1
            split_utility.append({"text": decrypt_question_text(question.text_ciphertext, question.text_nonce, request.app.state.settings.master_key_bytes), "question": question, "groups": len(groups), "coverage": sum(groups.values())})
    split_utility.sort(key=lambda item: (-item["groups"], -item["coverage"], item["question"].id))
    return templates.TemplateResponse(request=request, name="admin/cluster_detail.html", context={"admin": admin, "csrf_token": _csrf(request), "cluster": cluster, "members": [(person_id, names.get(person_id, person_id)) for person_id in sorted(member_ids)], "pairs": pairs, "names": names, "split_utility": split_utility})


@router.get("/identity-integrity/wizard", response_class=HTMLResponse)
def wizard(request: Request, pair_id: str | None = None, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    preview_facet_delta = 1
    preview_strong_delta = 1
    with request.app.state.session_factory() as db:
        snapshot = _latest(db)
        metric = _pair_for_wizard(db, snapshot, pair_id)
        question_views = []
        if metric:
            answers = _trait_map(db, {metric.person_a_id, metric.person_b_id})
            questions = db.scalars(select(Question).where(Question.active.is_(True), Question.privacy_level.in_(DISCOVERY_PRIVACY_LEVELS))).all()
            existing_facets = set()
            for question in questions:
                a = answers.get((metric.person_a_id, question.id))
                b = answers.get((metric.person_b_id, question.id))
                expected = abs(a.value - b.value) if a and b else 0.0
                if question.facet_tag and a and b and expected >= 1.0 and a.confidence >= 0.75 and b.confidence >= 0.75:
                    existing_facets.add(question.facet_tag)
                question_views.append({"question": question, "text": decrypt_question_text(question.text_ciphertext, question.text_nonce, request.app.state.settings.master_key_bytes), "a": a, "b": b, "missing": a is None or b is None, "expected_discriminator": expected >= 1.0})
            preview_facet_delta = 0 if "work" in existing_facets else 1
    question_views.sort(key=lambda item: (not item["missing"], not item["expected_discriminator"], item["question"].id))
    return templates.TemplateResponse(request=request, name="admin/integrity_wizard.html", context={"admin": admin, "csrf_token": _csrf(request), "snapshot": snapshot, "metric": metric, "question_views": question_views, "preview_strong_delta": preview_strong_delta, "preview_facet_delta": preview_facet_delta})


@router.post("/identity-integrity/wizard/traits")
def wizard_traits(
    request: Request,
    pair_id: str = Form(...),
    question_id: str = Form(...),
    a_value: float = Form(...),
    a_confidence: float = Form(...),
    b_value: float = Form(...),
    b_confidence: float = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    if a_value not in ANSWER_VALUES or b_value not in ANSWER_VALUES or not 0 <= a_confidence <= 1 or not 0 <= b_confidence <= 1:
        raise HTTPException(status_code=400, detail="invalid TraitAnswer value")
    with request.app.state.session_factory() as db:
        metric = db.get(IdentityPairMetric, pair_id)
        question = db.get(Question, question_id)
        if metric is None or question is None or question.privacy_level not in DISCOVERY_PRIVACY_LEVELS:
            raise HTTPException(status_code=400, detail="invalid Pair or Discovery Question")
        mark_latest_stale(db, actor_type="admin", actor_id=admin.id, reason="wizard.traits")
        for person_id, value, confidence in ((metric.person_a_id, a_value, a_confidence), (metric.person_b_id, b_value, b_confidence)):
            answer = db.get(TraitAnswer, (person_id, question_id))
            if answer is None:
                answer = TraitAnswer(person_id=person_id, question_id=question_id)
                db.add(answer)
            answer.value = value
            answer.confidence = confidence
        record_audit(db, actor_type="admin", event_type="trait.updated", actor_id=admin.id, target_type="pair", target_id=pair_id, metadata={"question_id": question_id, "source": "integrity_wizard"})
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="pair", target_id=pair_id, metadata={"reason": "wizard.traits"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse("/admin/identity-integrity/wizard", status_code=303)


@router.post("/identity-integrity/wizard/question")
def wizard_question(
    request: Request,
    pair_id: str = Form(...),
    text: str = Form(...),
    privacy_level: str = Form(...),
    facet_tag: str = Form(""),
    a_value: float = Form(...),
    b_value: float = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    text = text.strip()
    if not text or len(text) > 500:
        raise HTTPException(status_code=400, detail="question text must be 1-500 characters")
    if privacy_level not in DISCOVERY_PRIVACY_LEVELS or a_value not in ANSWER_VALUES or b_value not in ANSWER_VALUES:
        raise HTTPException(status_code=400, detail="Wizard question must be a Discovery question with valid values")
    with request.app.state.session_factory() as db:
        metric = db.get(IdentityPairMetric, pair_id)
        if metric is None:
            raise HTTPException(status_code=404, detail="Pair not found")
        mark_latest_stale(db, actor_type="admin", actor_id=admin.id, reason="wizard.question")
        nonce, ciphertext = encrypt_question_text(text.strip(), request.app.state.settings.master_key_bytes)
        question = Question(text_ciphertext=ciphertext, text_nonce=nonce, privacy_level=privacy_level, answer_scale="five_point", weight=1.0, facet_tag=facet_tag.strip() or None, active=True)
        db.add(question)
        db.flush()
        db.add_all([TraitAnswer(person_id=metric.person_a_id, question_id=question.id, value=a_value, confidence=1.0), TraitAnswer(person_id=metric.person_b_id, question_id=question.id, value=b_value, confidence=1.0)])
        record_audit(db, actor_type="admin", event_type="question.created", actor_id=admin.id, target_type="pair", target_id=pair_id, metadata={"source": "integrity_wizard"})
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="pair", target_id=pair_id, metadata={"reason": "wizard.question"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse("/admin/identity-integrity/wizard", status_code=303)


@router.get("/simulator", response_class=HTMLResponse)
def simulator_page(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        people = db.scalars(select(Person).where(Person.status == "active").order_by(Person.id)).all()
        names = _person_names(db, {person.id for person in people}, request.app.state.settings.master_key_bytes) if people else {}
    return templates.TemplateResponse(request=request, name="admin/simulator.html", context={"admin": admin, "csrf_token": _csrf(request), "people": [(person.id, names.get(person.id, person.id)) for person in people], "result": None})


@router.post("/simulator", response_class=HTMLResponse)
def simulator_run(request: Request, target_person_id: str = Form(...), profile: str = Form("EXACT"), seed: int = Form(0), csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        people = db.scalars(select(Person).where(Person.status == "active").order_by(Person.id)).all()
        questions_db = db.scalars(select(Question).where(Question.active.is_(True))).all()
        answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id.in_([person.id for person in people]))).all() if people else []
        answer_map: dict[str, dict[str, TraitValue]] = {}
        for answer in answers:
            if answer.value in ANSWER_VALUES:
                answer_map.setdefault(answer.person_id, {})[answer.question_id] = TraitValue(answer.value, answer.confidence)
        profiles = [PersonProfile(person.id, answer_map.get(person.id, {})) for person in people]
        target = next((person for person in profiles if person.id == target_person_id), None)
        if target is None:
            raise HTTPException(status_code=404, detail="Person not found")
        questions = [DiscoveryQuestion(question.id, question.privacy_level, question.weight, question.facet_tag, question.active) for question in questions_db if question.privacy_level in DISCOVERY_PRIVACY_LEVELS]
        result = simulate(target, profiles, questions, profile=NoiseProfile(profile), seed=seed, config=IdentityEngineConfig(max_questions=request.app.state.settings.identity_max_questions))
        names = _person_names(db, {person.id for person in people}, request.app.state.settings.master_key_bytes)
    return templates.TemplateResponse(request=request, name="admin/simulator.html", context={"admin": admin, "csrf_token": _csrf(request), "people": [(person.id, names.get(person.id, person.id)) for person in people], "result": result})
