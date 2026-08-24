"""JSON Admin API required by SPEC-080.

The HTML admin routes remain the primary browser surface; this router exposes
the same server-side authorization and encryption boundaries to integrations.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.models.admin import AdminUser
from app.models.asset import Asset
from app.models.identity import Person, Question, TraitAnswer
from app.models.integrity import IdentityCluster, IdentityIntegritySnapshot, IdentityPairMetric
from app.models.verification import VerificationAnswerDigest
from app.routes.admin_authoring import (
    DISCOVERY_PRIVACY_LEVELS,
    VALID_ANSWER_SCALES,
    VALID_PRIVACY_LEVELS,
    VALID_PERSON_STATUSES,
    _validate_person_input,
    _validate_question_input,
)
from app.security.admin_auth import require_admin, validate_admin_csrf
from app.services.assets import asset_display_name, create_asset
from app.services.audit import record_audit
from app.services.identity.engine import IdentityEngineConfig
from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile, TraitValue
from app.services.identity.simulator import NoiseProfile, simulate
from app.services.identity_integrity import recompute_incremental, recompute_integrity
from app.services.metadata import decrypt_person_name, decrypt_question_text, encrypt_person_name, encrypt_question_text, encrypt_trait_note
from app.services.recovery import create_recovery_record
from app.services.verification import create_challenge


router = APIRouter(prefix="/api/admin", tags=["admin-api"])


class PersonCreateRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    status: str = "active"
    csrf_token: str | None = None


class QuestionCreateRequest(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    privacy_level: str
    answer_scale: str = "five_point"
    weight: float = Field(default=1.0, gt=0, le=100)
    facet_tag: str = ""
    active: bool = True
    csrf_token: str | None = None


class TraitItem(BaseModel):
    question_id: str = Field(min_length=1, max_length=64)
    value: float
    confidence: float
    source_note: str = ""


class TraitsRequest(BaseModel):
    answers: list[TraitItem] = Field(default_factory=list, max_length=100)
    csrf_token: str | None = None


class ChallengeRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=500)
    answers: list[str] = Field(min_length=1, max_length=50)
    csrf_token: str | None = None


class SimulatorRequest(BaseModel):
    target_person_id: str = Field(min_length=1, max_length=64)
    profile: str = "EXACT"
    seed: int = 0
    csrf_token: str | None = None


class RecoveryKeyRequest(BaseModel):
    recovery_key: str = Field(min_length=32, max_length=256)
    csrf_token: str | None = None


def _csrf(request: Request, token: str | None) -> None:
    submitted = token or request.headers.get("x-csrf-token")
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, submitted):
            raise HTTPException(status_code=403, detail="CSRF validation failed")


def _person_json(person: Person, master_key: bytes) -> dict[str, object]:
    return {"id": person.id, "display_name": decrypt_person_name(person.display_name_ciphertext, person.display_name_nonce, master_key), "status": person.status, "created_at": person.created_at.isoformat()}


def _question_json(question: Question, master_key: bytes) -> dict[str, object]:
    return {"id": question.id, "text": decrypt_question_text(question.text_ciphertext, question.text_nonce, master_key), "privacy_level": question.privacy_level, "answer_scale": question.answer_scale, "weight": question.weight, "facet_tag": question.facet_tag, "active": question.active}


@router.get("/people")
def api_people(request: Request, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        people = db.scalars(select(Person).order_by(Person.created_at.desc())).all()
    return {"people": [_person_json(person, request.app.state.settings.master_key_bytes) for person in people]}


@router.post("/people", status_code=201)
def api_person_create(request: Request, body: PersonCreateRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, body.csrf_token)
    display_name, status = _validate_person_input(body.display_name, body.status)
    nonce, ciphertext = encrypt_person_name(display_name, request.app.state.settings.master_key_bytes)
    with request.app.state.session_factory() as db:
        person = Person(display_name_ciphertext=ciphertext, display_name_nonce=nonce, status=status)
        db.add(person)
        db.flush()
        record_audit(db, actor_type="admin", event_type="person.created", actor_id=admin.id, target_type="person", target_id=person.id)
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="person", target_id=person.id, metadata={"reason": "person.created"})
        db.commit()
        payload = _person_json(person, request.app.state.settings.master_key_bytes)
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return {"person": payload}


@router.post("/questions", status_code=201)
def api_question_create(request: Request, body: QuestionCreateRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, body.csrf_token)
    text, privacy, scale, weight, facet, active = _validate_question_input(body.text, body.privacy_level, body.answer_scale, str(body.weight), body.facet_tag, body.active)
    nonce, ciphertext = encrypt_question_text(text, request.app.state.settings.master_key_bytes)
    with request.app.state.session_factory() as db:
        question = Question(text_ciphertext=ciphertext, text_nonce=nonce, privacy_level=privacy, answer_scale=scale, weight=weight, facet_tag=facet, active=active)
        db.add(question)
        db.flush()
        record_audit(db, actor_type="admin", event_type="question.created", actor_id=admin.id, target_type="question", target_id=question.id)
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="question", target_id=question.id, metadata={"reason": "question.created"})
        db.commit()
        payload = _question_json(question, request.app.state.settings.master_key_bytes)
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return {"question": payload}


@router.post("/people/{person_id}/traits")
def api_traits(request: Request, person_id: str, body: TraitsRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, body.csrf_token)
    with request.app.state.session_factory() as db:
        if db.get(Person, person_id) is None:
            raise HTTPException(status_code=404, detail="Person not found")
        changed = 0
        for item in body.answers:
            if item.question_id == "" or item.value not in ANSWER_VALUES or not 0 <= item.confidence <= 1:
                raise HTTPException(status_code=400, detail="invalid TraitAnswer")
            question = db.get(Question, item.question_id)
            if question is None or question.privacy_level == "L4_VERIFICATION_ONLY":
                raise HTTPException(status_code=400, detail="invalid Discovery Question")
            answer = db.get(TraitAnswer, (person_id, item.question_id))
            if answer is None:
                answer = TraitAnswer(person_id=person_id, question_id=item.question_id)
                db.add(answer)
            answer.value = item.value
            answer.confidence = item.confidence
            if item.source_note:
                answer.source_note_nonce, answer.source_note_ciphertext = encrypt_trait_note(item.source_note, request.app.state.settings.master_key_bytes)
            else:
                answer.source_note_nonce = answer.source_note_ciphertext = None
            changed += 1
        record_audit(db, actor_type="admin", event_type="trait.updated", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"question_count": changed})
        record_audit(db, actor_type="admin", event_type="identity_integrity.stale", actor_id=admin.id, target_type="person", target_id=person_id, metadata={"reason": "trait.updated"})
        db.commit()
    recompute_incremental(request.app.state.db_engine, request.app.state.settings)
    return {"person_id": person_id, "updated": changed}


@router.post("/people/{person_id}/challenges", status_code=201)
def api_challenge(request: Request, person_id: str, body: ChallengeRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, body.csrf_token)
    with request.app.state.session_factory() as db:
        challenge = create_challenge(db, request.app.state.settings, person_id=person_id, prompt=body.prompt, answers=body.answers, admin_id=admin.id)
        db.commit()
        return {"challenge": {"id": challenge.id, "person_id": challenge.person_id, "active": challenge.active}}


@router.post("/people/{person_id}/assets", status_code=201)
async def api_asset(request: Request, person_id: str, file: UploadFile = File(...), display_name: str = Form(""), csrf_token: str | None = Form(None), admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, csrf_token)
    plaintext = await file.read(request.app.state.settings.asset_max_upload_bytes + 1)
    if len(plaintext) > request.app.state.settings.asset_max_upload_bytes:
        raise HTTPException(status_code=413, detail="asset exceeds configured upload limit")
    with request.app.state.session_factory() as db:
        asset = create_asset(db, request.app.state.settings, person_id=person_id, display_name=display_name.strip() or (file.filename or "asset.bin"), mime_type=file.content_type or "application/octet-stream", plaintext=plaintext)
        record_audit(db, actor_type="admin", event_type="asset.uploaded", actor_id=admin.id, target_type="asset", target_id=asset.id, metadata={"person_id": person_id, "size_plain": asset.size_plain})
        db.commit()
        return {"asset": {"id": asset.id, "person_id": asset.person_id, "display_name": asset_display_name(asset, request.app.state.settings), "mime_type": asset.mime_type, "size": asset.size_plain, "active": asset.active}}


@router.post("/simulator")
def api_simulator(request: Request, body: SimulatorRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, body.csrf_token)
    with request.app.state.session_factory() as db:
        people = db.scalars(select(Person).where(Person.status == "active").order_by(Person.id)).all()
        questions_db = db.scalars(select(Question).where(Question.active.is_(True))).all()
        answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id.in_([person.id for person in people]))).all() if people else []
        answer_map: dict[str, dict[str, TraitValue]] = {}
        for answer in answers:
            if answer.value in ANSWER_VALUES:
                answer_map.setdefault(answer.person_id, {})[answer.question_id] = TraitValue(answer.value, answer.confidence)
        profiles = [PersonProfile(person.id, answer_map.get(person.id, {})) for person in people]
        target = next((person for person in profiles if person.id == body.target_person_id), None)
        if target is None:
            raise HTTPException(status_code=404, detail="Person not found")
        try:
            noise_profile = NoiseProfile(body.profile)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid simulator profile") from exc
        questions = [DiscoveryQuestion(question.id, question.privacy_level, question.weight, question.facet_tag, question.active) for question in questions_db if question.privacy_level in DISCOVERY_PRIVACY_LEVELS]
        result = simulate(target, profiles, questions, profile=noise_profile, seed=body.seed, config=IdentityEngineConfig(max_questions=request.app.state.settings.identity_max_questions))
    return {"result": {"status": result.status, "guessed_person_id": result.guessed_person_id, "score_margin": result.score_margin, "algorithm_version": result.algorithm_version}}


@router.get("/identity-integrity")
def api_integrity(request: Request, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
    return {"snapshot": None if snapshot is None else {"id": snapshot.id, "mode": snapshot.mode, "status": snapshot.status, "blocking_pair_count": snapshot.blocking_pair_count, "warning_pair_count": snapshot.warning_pair_count, "cluster_count": snapshot.cluster_count, "worst_confusion_rate": snapshot.worst_confusion_rate}}


@router.post("/identity-integrity/recompute")
def api_integrity_recompute(request: Request, csrf_token: str | None = None, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        record_audit(db, actor_type="admin", event_type="identity_integrity.recompute.started", actor_id=admin.id)
        db.commit()
    snapshot = recompute_integrity(request.app.state.db_engine, request.app.state.settings, mode="full")
    with request.app.state.session_factory() as db:
        record_audit(db, actor_type="admin", event_type="identity_integrity.recompute.completed", actor_id=admin.id, metadata={"snapshot_id": snapshot.id, "status": snapshot.status})
        db.commit()
    return {"snapshot": {"id": snapshot.id, "status": snapshot.status, "blocking_pair_count": snapshot.blocking_pair_count, "warning_pair_count": snapshot.warning_pair_count}}


@router.get("/identity-integrity/pairs")
def api_integrity_pairs(request: Request, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
        metrics = db.scalars(select(IdentityPairMetric).where(IdentityPairMetric.snapshot_id == snapshot.id).order_by(IdentityPairMetric.risk.desc()) if snapshot else select(IdentityPairMetric).where(False)).all()
    return {"snapshot_id": snapshot.id if snapshot else None, "pairs": [{"id": metric.id, "person_a_id": metric.person_a_id, "person_b_id": metric.person_b_id, "risk": metric.risk, "confusion_a_to_b": metric.confusion_a_to_b, "confusion_b_to_a": metric.confusion_b_to_a, "common_question_count": metric.common_question_count} for metric in metrics]}


@router.get("/identity-integrity/pairs/{pair_id}")
def api_integrity_pair(request: Request, pair_id: str, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        metric = db.get(IdentityPairMetric, pair_id)
        if metric is None:
            raise HTTPException(status_code=404, detail="Pair not found")
    return {"pair": {"id": metric.id, "snapshot_id": metric.snapshot_id, "person_a_id": metric.person_a_id, "person_b_id": metric.person_b_id, "risk": metric.risk, "trait_similarity": metric.trait_similarity, "confusion_a_to_b": metric.confusion_a_to_b, "confusion_b_to_a": metric.confusion_b_to_a, "strong_discriminator_count": metric.strong_discriminator_count}}


@router.get("/identity-integrity/clusters")
def api_integrity_clusters(request: Request, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        clusters = db.scalars(select(IdentityCluster).order_by(IdentityCluster.cluster_id)).all()
    return {"clusters": [{"id": cluster.id, "snapshot_id": cluster.snapshot_id, "cluster_id": cluster.cluster_id, "risk": cluster.risk, "member_person_ids": cluster.member_person_ids, "worst_pair": cluster.worst_pair} for cluster in clusters]}


@router.get("/identity-integrity/clusters/{cluster_id}")
def api_integrity_cluster(request: Request, cluster_id: str, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        cluster = db.get(IdentityCluster, cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
    return {"cluster": {"id": cluster.id, "snapshot_id": cluster.snapshot_id, "cluster_id": cluster.cluster_id, "risk": cluster.risk, "member_person_ids": cluster.member_person_ids, "worst_pair": cluster.worst_pair}}


@router.post("/identity-integrity/preview-question")
def api_integrity_preview_question(request: Request, payload: dict[str, object], admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _csrf(request, str(payload.get("csrf_token")) if payload.get("csrf_token") is not None else None)
    pair_id = str(payload.get("pair_id", ""))
    question_id = str(payload.get("question_id", ""))
    with request.app.state.session_factory() as db:
        pair = db.get(IdentityPairMetric, pair_id)
        question = db.get(Question, question_id)
        valid = pair is not None and question is not None and question.privacy_level in DISCOVERY_PRIVACY_LEVELS
    return {"preview": {"valid": valid, "pair_id": pair_id, "question_id": question_id, "strong_discriminator_delta": 1 if valid else 0}}
