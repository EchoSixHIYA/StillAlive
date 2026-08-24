"""Phase 2 Person, Question, and TraitAnswer web authoring routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app.models.admin import AdminUser
from app.models.asset import Asset
from app.models.identity import Person, Question, TraitAnswer
from app.models.integrity import IdentityIntegritySnapshot, IdentityPairMetric
from app.models.verification import VerificationAnswerDigest, VerificationChallenge
from app.security.admin_auth import require_admin, validate_admin_csrf
from app.services.audit import record_audit
from app.services.assets import asset_display_name, create_asset
from app.services.identity_integrity import mark_latest_stale, recompute_incremental
from app.services.verification import create_challenge, decrypt_prompt
from app.services.metadata import (
    decrypt_person_name,
    decrypt_question_text,
    decrypt_trait_note,
    encrypt_person_name,
    encrypt_question_text,
    encrypt_trait_note,
)


router = APIRouter(prefix="/admin", tags=["admin-authoring"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))

VALID_PERSON_STATUSES = {"active", "disabled", "archived"}
VALID_PRIVACY_LEVELS = {"L0_PUBLIC", "L1_RELATION", "L2_PRIVATE", "L3_SENSITIVE", "L4_VERIFICATION_ONLY"}
VALID_ANSWER_SCALES = {"five_point", "boolean"}
DISCOVERY_PRIVACY_LEVELS = VALID_PRIVACY_LEVELS - {"L4_VERIFICATION_ONLY"}


def _csrf_token(request: Request) -> str:
    return request.cookies.get("still_alive_admin_csrf", "")


def _require_csrf(request: Request, form_token: str | None) -> None:
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, form_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")


def _bool_field(value: str | None) -> bool:
    return value is not None and value.lower() in {"1", "true", "on", "yes"}


def _person_view(person: Person, master_key: bytes) -> dict[str, object]:
    return {
        "person": person,
        "display_name": decrypt_person_name(person.display_name_ciphertext, person.display_name_nonce, master_key),
    }


def _question_view(question: Question, master_key: bytes, coverage: int = 0) -> dict[str, object]:
    return {
        "question": question,
        "text": decrypt_question_text(question.text_ciphertext, question.text_nonce, master_key),
        "coverage": coverage,
    }


def _validate_person_input(display_name: str, status: str) -> tuple[str, str]:
    display_name = display_name.strip()
    if not display_name or len(display_name) > 200:
        raise HTTPException(status_code=400, detail="display_name must be 1-200 characters")
    if status not in VALID_PERSON_STATUSES:
        raise HTTPException(status_code=400, detail="invalid person status")
    return display_name, status


def _validate_question_input(
    text: str,
    privacy_level: str,
    answer_scale: str,
    weight: str,
    facet_tag: str,
    active: bool,
) -> tuple[str, str, str, float, str | None, bool]:
    text = text.strip()
    facet_tag = facet_tag.strip()
    if not text or len(text) > 500:
        raise HTTPException(status_code=400, detail="question text must be 1-500 characters")
    if privacy_level not in VALID_PRIVACY_LEVELS:
        raise HTTPException(status_code=400, detail="invalid privacy level")
    if answer_scale not in VALID_ANSWER_SCALES:
        raise HTTPException(status_code=400, detail="invalid answer scale")
    try:
        numeric_weight = float(weight)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="weight must be a number") from exc
    if not 0 < numeric_weight <= 100:
        raise HTTPException(status_code=400, detail="weight must be between 0 and 100")
    if len(facet_tag) > 64:
        raise HTTPException(status_code=400, detail="facet_tag must be at most 64 characters")
    if privacy_level == "L4_VERIFICATION_ONLY" and active:
        raise HTTPException(status_code=409, detail="L4_VERIFICATION_ONLY cannot be active in Discovery")
    return text, privacy_level, answer_scale, numeric_weight, facet_tag or None, active


@router.get("/people", response_class=HTMLResponse)
def people_list(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        people = db.scalars(select(Person).order_by(Person.created_at.desc())).all()
    master_key = request.app.state.settings.master_key_bytes
    views = [_person_view(person, master_key) for person in people]
    return templates.TemplateResponse(
        request=request,
        name="admin/people_list.html",
        context={"admin": admin, "csrf_token": _csrf_token(request), "people": views},
    )


@router.get("/people/new", response_class=HTMLResponse)
def person_new(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="admin/person_form.html",
        context={"admin": admin, "csrf_token": _csrf_token(request), "person": None, "display_name": "", "status": "active", "error": None},
    )


@router.post("/people")
def person_create(
    request: Request,
    display_name: str = Form(...),
    status: str = Form("active"),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    display_name, status = _validate_person_input(display_name, status)
    settings = request.app.state.settings
    nonce, ciphertext = encrypt_person_name(display_name, settings.master_key_bytes)
    with request.app.state.session_factory() as db:
        mark_latest_stale(db, actor_type="admin", actor_id=admin.id, reason="person.created")
        person = Person(display_name_ciphertext=ciphertext, display_name_nonce=nonce, status=status)
        db.add(person)
        db.flush()
        record_audit(db, actor_type="admin", event_type="person.created", actor_id=admin.id, target_type="person", target_id=person.id)
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="person", target_id=person.id, metadata={"reason": "person.created"})
        db.commit()
        person_id = person.id
    recompute_incremental(request.app.state.db_engine, settings)
    return RedirectResponse(f"/admin/people/{person_id}", status_code=303)


@router.get("/people/{person_id}", response_class=HTMLResponse)
def person_detail(request: Request, person_id: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        person = db.get(Person, person_id)
        if person is None:
            raise HTTPException(status_code=404, detail="Person not found")
        questions = db.scalars(select(Question).order_by(Question.created_at.asc())).all()
        answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id == person_id)).all()
        challenges = db.scalars(select(VerificationChallenge).where(VerificationChallenge.person_id == person_id).order_by(VerificationChallenge.created_at.desc())).all()
        challenge_views = [
            {
                "challenge": challenge,
                "prompt": decrypt_prompt(challenge, request.app.state.settings),
                "answer_count": db.scalar(select(func.count(VerificationAnswerDigest.id)).where(VerificationAnswerDigest.challenge_id == challenge.id)) or 0,
            }
            for challenge in challenges
        ]
        assets = db.scalars(select(Asset).where(Asset.person_id == person_id).order_by(Asset.created_at.desc())).all()
        asset_views = [{"asset": asset, "display_name": asset_display_name(asset, request.app.state.settings)} for asset in assets]
        latest_snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
        closest_metric = None
        if latest_snapshot:
            metrics = db.scalars(select(IdentityPairMetric).where(IdentityPairMetric.snapshot_id == latest_snapshot.id, (IdentityPairMetric.person_a_id == person_id) | (IdentityPairMetric.person_b_id == person_id))).all()
            closest_metric = max(metrics, key=lambda metric: max(metric.confusion_a_to_b, metric.confusion_b_to_a), default=None)
    answer_by_question = {answer.question_id: answer for answer in answers}
    master_key = request.app.state.settings.master_key_bytes
    closest_person = None
    if closest_metric:
        closest_id = closest_metric.person_b_id if closest_metric.person_a_id == person_id else closest_metric.person_a_id
        with request.app.state.session_factory() as db:
            closest_person = db.get(Person, closest_id)
        if closest_person:
            closest_person = {"id": closest_person.id, "name": decrypt_person_name(closest_person.display_name_ciphertext, closest_person.display_name_nonce, master_key), "metric": closest_metric}
    question_views = []
    for question in questions:
        answer = answer_by_question.get(question.id)
        note = None
        if answer and answer.source_note_ciphertext and answer.source_note_nonce:
            note = decrypt_trait_note(answer.source_note_ciphertext, answer.source_note_nonce, master_key)
        question_views.append({"question": question, "text": decrypt_question_text(question.text_ciphertext, question.text_nonce, master_key), "answer": answer, "note": note})
    return templates.TemplateResponse(
        request=request,
        name="admin/person_detail.html",
        context={
            "admin": admin,
            "csrf_token": _csrf_token(request),
            "person": person,
            "display_name": decrypt_person_name(person.display_name_ciphertext, person.display_name_nonce, master_key),
            "question_views": question_views,
            "missing_count": sum(1 for item in question_views if item["question"].active and item["question"].privacy_level in DISCOVERY_PRIVACY_LEVELS and item["answer"] is None),
            "closest_person": closest_person,
            "challenge_views": challenge_views,
            "asset_views": asset_views,
        },
    )


@router.post("/people/{person_id}/traits")
async def traits_save(request: Request, person_id: str, admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    form = await request.form()
    _require_csrf(request, form.get("csrf_token"))
    with request.app.state.session_factory() as db:
        person = db.get(Person, person_id)
        if person is None:
            raise HTTPException(status_code=404, detail="Person not found")
        questions = db.scalars(select(Question).where(Question.privacy_level != "L4_VERIFICATION_ONLY")).all()
        changed = 0
        for question in questions:
            value_raw = form.get(f"value_{question.id}")
            confidence_raw = form.get(f"confidence_{question.id}")
            if value_raw is None and confidence_raw is None:
                continue
            try:
                value = float(value_raw or 0)
                confidence = float(confidence_raw or 0)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Trait value and confidence must be numbers") from exc
            if not -1 <= value <= 1 or not 0 <= confidence <= 1:
                raise HTTPException(status_code=400, detail="Trait value/confidence out of range")
            note_raw = str(form.get(f"source_note_{question.id}") or "").strip()
            answer = db.get(TraitAnswer, (person_id, question.id))
            if answer is None:
                answer = TraitAnswer(person_id=person_id, question_id=question.id)
                db.add(answer)
            answer.value = value
            answer.confidence = confidence
            if note_raw:
                answer.source_note_nonce, answer.source_note_ciphertext = encrypt_trait_note(note_raw, request.app.state.settings.master_key_bytes)
            else:
                answer.source_note_nonce = None
                answer.source_note_ciphertext = None
            changed += 1
        if changed:
            record_audit(db, actor_type="admin", event_type="trait.updated", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"question_count": changed})
            record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"reason": "trait.updated"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse(f"/admin/people/{person_id}", status_code=303)


@router.post("/people/{person_id}/status")
def person_status(request: Request, person_id: str, status: str = Form(...), csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    if status not in VALID_PERSON_STATUSES:
        raise HTTPException(status_code=400, detail="invalid person status")
    with request.app.state.session_factory() as db:
        mark_latest_stale(db, actor_type="admin", actor_id=admin.id, reason="person.status")
        person = db.get(Person, person_id)
        if person is None:
            raise HTTPException(status_code=404, detail="Person not found")
        person.status = status
        record_audit(db, actor_type="admin", event_type="person.updated", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"status": status})
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"reason": "person.status"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse(f"/admin/people/{person_id}", status_code=303)


@router.get("/questions", response_class=HTMLResponse)
def questions_list(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        questions = db.scalars(select(Question).order_by(Question.created_at.desc())).all()
        views = []
        for question in questions:
            coverage = len({answer.person_id for answer in question.trait_answers})
            views.append(_question_view(question, request.app.state.settings.master_key_bytes, coverage))
    return templates.TemplateResponse(
        request=request,
        name="admin/questions_list.html",
        context={"admin": admin, "csrf_token": _csrf_token(request), "questions": views},
    )


@router.get("/questions/new", response_class=HTMLResponse)
def question_new(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="admin/question_form.html",
        context={"admin": admin, "csrf_token": _csrf_token(request), "question": None, "text": "", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": "", "active": True, "error": None},
    )


@router.post("/questions")
def question_create(
    request: Request,
    text: str = Form(...),
    privacy_level: str = Form(...),
    answer_scale: str = Form("five_point"),
    weight: str = Form("1.0"),
    facet_tag: str = Form(""),
    active: str | None = Form(None),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    text, privacy_level, answer_scale, numeric_weight, facet_tag, active_bool = _validate_question_input(text, privacy_level, answer_scale, weight, facet_tag, _bool_field(active))
    nonce, ciphertext = encrypt_question_text(text, request.app.state.settings.master_key_bytes)
    with request.app.state.session_factory() as db:
        mark_latest_stale(db, actor_type="admin", actor_id=admin.id, reason="question.created")
        question = Question(text_ciphertext=ciphertext, text_nonce=nonce, privacy_level=privacy_level, answer_scale=answer_scale, weight=numeric_weight, facet_tag=facet_tag, active=active_bool)
        db.add(question)
        db.flush()
        record_audit(db, actor_type="admin", event_type="question.created", actor_id=admin.id, target_type="question", target_id=question.id)
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="question", target_id=question.id, metadata={"reason": "question.created"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse("/admin/questions", status_code=303)


@router.get("/questions/{question_id}/edit", response_class=HTMLResponse)
def question_edit(request: Request, question_id: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        question = db.get(Question, question_id)
        if question is None:
            raise HTTPException(status_code=404, detail="Question not found")
    text = decrypt_question_text(question.text_ciphertext, question.text_nonce, request.app.state.settings.master_key_bytes)
    return templates.TemplateResponse(
        request=request,
        name="admin/question_form.html",
        context={"admin": admin, "csrf_token": _csrf_token(request), "question": question, "text": text, "privacy_level": question.privacy_level, "answer_scale": question.answer_scale, "weight": str(question.weight), "facet_tag": question.facet_tag or "", "active": question.active, "error": None},
    )


@router.post("/questions/{question_id}")
def question_update(
    request: Request,
    question_id: str,
    text: str = Form(...),
    privacy_level: str = Form(...),
    answer_scale: str = Form("five_point"),
    weight: str = Form("1.0"),
    facet_tag: str = Form(""),
    active: str | None = Form(None),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    text, privacy_level, answer_scale, numeric_weight, facet_tag, active_bool = _validate_question_input(text, privacy_level, answer_scale, weight, facet_tag, _bool_field(active))
    with request.app.state.session_factory() as db:
        question = db.get(Question, question_id)
        if question is None:
            raise HTTPException(status_code=404, detail="Question not found")
        nonce, ciphertext = encrypt_question_text(text, request.app.state.settings.master_key_bytes)
        question.text_ciphertext, question.text_nonce = ciphertext, nonce
        question.privacy_level = privacy_level
        question.answer_scale = answer_scale
        question.weight = numeric_weight
        question.facet_tag = facet_tag
        question.active = active_bool
        record_audit(db, actor_type="admin", event_type="question.updated", actor_id=admin.id, target_type="question", target_id=question_id)
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="question", target_id=question_id, metadata={"reason": "question.updated"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return RedirectResponse("/admin/questions", status_code=303)


@router.post("/people/{person_id}/challenges")
def challenge_create(
    request: Request,
    person_id: str,
    prompt: str = Form(...),
    answers: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        create_challenge(db, request.app.state.settings, person_id=person_id, prompt=prompt, answers=answers.splitlines(), admin_id=admin.id)
        db.commit()
    return RedirectResponse(f"/admin/people/{person_id}#verification", status_code=303)


@router.post("/people/{person_id}/assets")
async def asset_create_route(
    request: Request,
    person_id: str,
    file: UploadFile = File(...),
    display_name: str = Form(""),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    plaintext = await file.read(request.app.state.settings.asset_max_upload_bytes + 1)
    if len(plaintext) > request.app.state.settings.asset_max_upload_bytes:
        raise HTTPException(status_code=413, detail="asset exceeds configured upload limit")
    chosen_name = display_name.strip() or (file.filename or "asset.bin")
    with request.app.state.session_factory() as db:
        asset = create_asset(db, request.app.state.settings, person_id=person_id, display_name=chosen_name, mime_type=file.content_type or "application/octet-stream", plaintext=plaintext)
        record_audit(db, actor_type="admin", event_type="asset.uploaded", actor_id=admin.id, target_type="asset", target_id=asset.id, metadata={"person_id": person_id, "size_plain": asset.size_plain, "mime_type": asset.mime_type})
        db.commit()
    return RedirectResponse(f"/admin/people/{person_id}#assets", status_code=303)


@router.post("/people/{person_id}/assets/{asset_id}/status")
def asset_status(
    request: Request,
    person_id: str,
    asset_id: str,
    active: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    active_bool = active.strip().lower() in {"1", "true", "on", "yes"}
    with request.app.state.session_factory() as db:
        asset = db.get(Asset, asset_id)
        if asset is None or asset.person_id != person_id:
            raise HTTPException(status_code=404, detail="Asset not found")
        asset.active = active_bool
        record_audit(
            db,
            actor_type="admin",
            event_type="asset.enabled" if active_bool else "asset.disabled",
            actor_id=admin.id,
            target_type="asset",
            target_id=asset.id,
            metadata={"person_id": person_id},
        )
        db.commit()
    return RedirectResponse(f"/admin/people/{person_id}#assets", status_code=303)
