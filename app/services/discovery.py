"""Public Discovery Session orchestration around the pure Identity Engine."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.discovery import DiscoveryAnswer, DiscoverySession
from app.models.identity import Person, Question, TraitAnswer
from app.services.identity.engine import IdentityEngine, IdentityEngineConfig, IdentityDecision
from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile, TraitValue
from app.services.identity_integrity import DISCOVERY_PRIVACY_LEVELS
from app.services.metadata import decrypt_person_name, decrypt_question_text
from app.services.grants import asset_list
from app.services.audit import record_audit
from app.services.verification import verification_payload


PUBLIC_ANSWER_VALUES: dict[str, float] = {
    "yes": 1.0,
    "probably_yes": 0.5,
    "probably-yes": 0.5,
    "unknown": 0.0,
    "probably_no": -0.5,
    "probably-no": -0.5,
    "no": -1.0,
    "是": 1.0,
    "大概是": 0.5,
    "不知道": 0.0,
    "大概不是": -0.5,
    "不是": -1.0,
}


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _secret_hash(settings: Settings, value: str | None) -> bytes | None:
    if not value:
        return None
    secret = settings.session_secret.get_secret_value().encode("utf-8")
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).digest()


def normalize_public_answer(value: str) -> float:
    normalized = " ".join(value.strip().lower().split())
    if normalized in PUBLIC_ANSWER_VALUES:
        return PUBLIC_ANSWER_VALUES[normalized]
    try:
        numeric = float(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="answer must be yes/probably_yes/unknown/probably_no/no") from exc
    if numeric not in ANSWER_VALUES:
        raise HTTPException(status_code=400, detail="answer must be one of the five supported values")
    return numeric


def create_session(db: Session, settings: Settings, *, client_ip: str | None, user_agent: str | None) -> DiscoverySession:
    now = datetime.now(timezone.utc)
    session = DiscoverySession(
        status="active",
        created_at=now,
        expires_at=now + timedelta(minutes=settings.discovery_session_minutes),
        ip_hash=_secret_hash(settings, client_ip),
        ua_hash=_secret_hash(settings, user_agent),
    )
    db.add(session)
    db.flush()
    record_audit(db, actor_type="public", event_type="discovery.session.created", target_type="session", target_id=session.id)
    return session


def _load_engine(db: Session, session: DiscoverySession, settings: Settings) -> tuple[IdentityEngine, list[Question]]:
    people = db.scalars(select(Person).where(Person.status == "active", Person.delivery_enabled.is_(True)).order_by(Person.id)).all()
    questions = db.scalars(
        select(Question).where(Question.active.is_(True), Question.privacy_level.in_(DISCOVERY_PRIVACY_LEVELS)).order_by(Question.id)
    ).all()
    trait_answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id.in_([person.id for person in people]))).all() if people else []
    traits_by_person: dict[str, dict[str, TraitValue]] = {person.id: {} for person in people}
    for answer in trait_answers:
        if answer.value in ANSWER_VALUES:
            traits_by_person.setdefault(answer.person_id, {})[answer.question_id] = TraitValue(answer.value, answer.confidence)
    profiles = [PersonProfile(person.id, traits_by_person.get(person.id, {})) for person in people]
    engine_questions = [DiscoveryQuestion(question.id, question.privacy_level, question.weight, question.facet_tag, question.active) for question in questions]
    engine = IdentityEngine(profiles, engine_questions, IdentityEngineConfig(max_questions=settings.identity_max_questions))
    saved_answers = db.scalars(select(DiscoveryAnswer).where(DiscoveryAnswer.session_id == session.id).order_by(DiscoveryAnswer.created_at, DiscoveryAnswer.question_id)).all()
    for answer in saved_answers:
        if answer.question_id not in engine.questions or answer.question_id in engine.asked:
            continue
        engine.answer(answer.question_id, answer.normalized_value)
    engine.rejected_person_ids.update(session.rejected_ids())
    return engine, questions


def _question_payload(question: Question, settings: Settings) -> dict[str, str]:
    return {"id": question.id, "text": decrypt_question_text(question.text_ciphertext, question.text_nonce, settings.master_key_bytes)}


def _guess_name(db: Session, person_id: str | None, settings: Settings) -> str | None:
    if not person_id:
        return None
    person = db.get(Person, person_id)
    if person is None or person.status != "active" or not person.delivery_enabled:
        return None
    return decrypt_person_name(person.display_name_ciphertext, person.display_name_nonce, settings.master_key_bytes)


def _decision_payload(db: Session, session: DiscoverySession, engine: IdentityEngine, questions: list[Question], settings: Settings, decision: IdentityDecision | None = None) -> dict[str, object]:
    decision = decision or engine.decision()
    if decision.status == "guess" and decision.guess_person_id:
        session.status = "guess"
        session.guessed_person_id = decision.guess_person_id
        record_audit(db, actor_type="public", event_type="discovery.guess.presented", target_type="session", target_id=session.id, metadata={"person_id": decision.guess_person_id})
        db.commit()
        return {"session_id": session.id, "state": "GUESS", "guess": {"person_id": decision.guess_person_id, "display_name": _guess_name(db, decision.guess_person_id, settings)}}
    if decision.status == "question":
        question = engine.next_question()
        if question is None:
            return {"session_id": session.id, "state": "UNABLE_TO_IDENTIFY"}
        question_row = next((item for item in questions if item.id == question.id), None)
        if question_row is None:
            return {"session_id": session.id, "state": "UNABLE_TO_IDENTIFY"}
        return {"session_id": session.id, "state": "QUESTION", "question": _question_payload(question_row, settings)}
    if decision.status == "locked":
        session.status = "locked"
        db.commit()
        return {"session_id": session.id, "state": "LOCKED"}
    if session.status == "expired":
        return {"session_id": session.id, "state": "EXPIRED"}
    if session.status == "verification":
        return {"session_id": session.id, "state": "VERIFICATION"}
    if session.status == "verified":
        return {"session_id": session.id, "state": "VERIFIED"}
    return {"session_id": session.id, "state": "UNABLE_TO_IDENTIFY"}


def session_payload(db: Session, session: DiscoverySession, settings: Settings) -> dict[str, object]:
    if session.status not in {"expired", "locked", "verified"} and datetime.now(timezone.utc) >= _as_utc(session.expires_at):
        session.status = "expired"
        db.commit()
        return {"session_id": session.id, "state": "EXPIRED"}
    if session.status == "guess":
        return {"session_id": session.id, "state": "GUESS", "guess": {"person_id": session.guessed_person_id, "display_name": _guess_name(db, session.guessed_person_id, settings)}}
    if session.status == "verified":
        return asset_list(db, session, settings)
    if session.status in {"verification", "locked"}:
        return verification_payload(db, session, settings) if session.status != "locked" else {"session_id": session.id, "state": "LOCKED"}
    engine, questions = _load_engine(db, session, settings)
    return _decision_payload(db, session, engine, questions, settings)


def answer_session(db: Session, session: DiscoverySession, settings: Settings, *, question_id: str, answer: str) -> dict[str, object]:
    if session.status != "active":
        raise HTTPException(status_code=409, detail="session is not accepting Discovery answers")
    if datetime.now(timezone.utc) >= _as_utc(session.expires_at):
        session.status = "expired"
        db.commit()
        raise HTTPException(status_code=410, detail="session expired")
    value = normalize_public_answer(answer)
    engine, questions = _load_engine(db, session, settings)
    try:
        decision = engine.answer(question_id, value)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="question is not available for this session") from exc
    if db.get(DiscoveryAnswer, (session.id, question_id)) is not None:
        raise HTTPException(status_code=400, detail="question has already been answered")
    db.add(DiscoveryAnswer(session_id=session.id, question_id=question_id, normalized_value=value))
    session.question_count = engine.question_count
    db.commit()
    return _decision_payload(db, session, engine, questions, settings, decision)


def decide_guess(db: Session, session: DiscoverySession, settings: Settings, *, accepted: bool) -> dict[str, object]:
    if session.status != "guess" or not session.guessed_person_id:
        raise HTTPException(status_code=409, detail="session is not awaiting a guess decision")
    guessed_id = session.guessed_person_id
    if accepted:
        session.confirmed_person_id = guessed_id
        session.status = "verification"
        record_audit(db, actor_type="public", event_type="discovery.guess.accepted", target_type="session", target_id=session.id)
        db.commit()
        return {"session_id": session.id, "state": "VERIFICATION"}
    rejected = session.rejected_ids()
    rejected.add(guessed_id)
    session.failed_guess_count += 1
    session.guessed_person_id = None
    session.set_rejected_ids(rejected)
    record_audit(db, actor_type="public", event_type="discovery.guess.rejected", target_type="session", target_id=session.id, metadata={"failed_guess_count": session.failed_guess_count})
    if session.failed_guess_count >= 3:
        session.status = "locked"
        db.commit()
        return {"session_id": session.id, "state": "LOCKED"}
    session.status = "active"
    db.commit()
    return session_payload(db, session, settings)
