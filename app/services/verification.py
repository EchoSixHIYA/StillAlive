"""Verification challenge authoring and constant-time public verification."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unicodedata
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.discovery import DiscoverySession
from app.models.identity import Person
from app.models.verification import VerificationAnswerDigest, VerificationAttempt, VerificationChallenge
from app.services.audit import record_audit
from app.security.crypto import decrypt_secret, encrypt_secret


NORMALIZATION_VERSION = "v1"
BACKOFF_SECONDS = (2, 5, 15, 60)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def normalize_answer(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    normalized = " ".join(normalized.split()).lower()
    return normalized.rstrip(".,!?;:，。！？；：")


def answer_hmac(settings: Settings, *, person_id: str, challenge_id: str, normalized_answer: str) -> bytes:
    pepper = settings.answer_pepper.get_secret_value().encode("utf-8")
    message = "|".join((person_id, challenge_id, NORMALIZATION_VERSION, normalized_answer)).encode("utf-8")
    return hmac.new(pepper, message, hashlib.sha256).digest()


def create_challenge(db: Session, settings: Settings, *, person_id: str, prompt: str, answers: list[str], admin_id: str) -> VerificationChallenge:
    prompt = prompt.strip()
    normalized_answers = {normalize_answer(answer) for answer in answers if normalize_answer(answer)}
    if not prompt or len(prompt) > 500:
        raise HTTPException(status_code=400, detail="prompt must be 1-500 characters")
    if not normalized_answers:
        raise HTTPException(status_code=400, detail="at least one non-empty answer is required")
    person = db.get(Person, person_id)
    if person is None:
        raise HTTPException(status_code=404, detail="Person not found")
    nonce, ciphertext = encrypt_secret(prompt, settings.master_key_bytes, context=b"still-alive/verification/prompt/v1")
    challenge = VerificationChallenge(person_id=person_id, prompt_ciphertext=ciphertext, prompt_nonce=nonce, active=True)
    db.add(challenge)
    db.flush()
    for normalized_answer in normalized_answers:
        db.add(VerificationAnswerDigest(challenge_id=challenge.id, normalization_version=NORMALIZATION_VERSION, answer_hmac=answer_hmac(settings, person_id=person_id, challenge_id=challenge.id, normalized_answer=normalized_answer)))
    record_audit(db, actor_type="admin", event_type="challenge.created", actor_id=admin_id, target_type="person", target_id=person_id, metadata={"challenge_id": challenge.id, "answer_count": len(normalized_answers)})
    record_audit(db, actor_type="admin", event_type="challenge.answer_digest.added", actor_id=admin_id, target_type="challenge", target_id=challenge.id, metadata={"answer_count": len(normalized_answers), "normalization_version": NORMALIZATION_VERSION})
    return challenge


def decrypt_prompt(challenge: VerificationChallenge, settings: Settings) -> str:
    return decrypt_secret(challenge.prompt_ciphertext, challenge.prompt_nonce, settings.master_key_bytes, context=b"still-alive/verification/prompt/v1")


def _choose_challenge(db: Session, session: DiscoverySession) -> VerificationChallenge | None:
    challenges = db.scalars(select(VerificationChallenge).where(VerificationChallenge.person_id == session.confirmed_person_id, VerificationChallenge.active.is_(True)).order_by(VerificationChallenge.id)).all()
    if not challenges:
        return None
    used = set(db.scalars(select(VerificationAttempt.challenge_id).where(VerificationAttempt.session_id == session.id)).all())
    available = [challenge for challenge in challenges if challenge.id not in used] or challenges
    return secrets.choice(available)


def verification_payload(db: Session, session: DiscoverySession, settings: Settings) -> dict[str, object]:
    if session.status == "verification" and datetime.now(timezone.utc) >= _as_utc(session.expires_at):
        session.status = "expired"
        db.commit()
        return {"session_id": session.id, "state": "EXPIRED"}
    if session.status == "verified":
        return {"session_id": session.id, "state": "VERIFIED"}
    if session.status == "locked":
        return {"session_id": session.id, "state": "LOCKED"}
    if session.status != "verification" or not session.confirmed_person_id:
        raise HTTPException(status_code=409, detail="session is not ready for verification")
    challenge = _choose_challenge(db, session)
    if challenge is None:
        return {"session_id": session.id, "state": "VERIFICATION", "challenge": None, "message": "No active verification challenge is configured."}
    failures = db.scalar(select(func.count(VerificationAttempt.id)).where(VerificationAttempt.session_id == session.id, VerificationAttempt.challenge_id == challenge.id, VerificationAttempt.success.is_(False))) or 0
    last_failure = db.scalar(select(VerificationAttempt).where(VerificationAttempt.session_id == session.id, VerificationAttempt.challenge_id == challenge.id, VerificationAttempt.success.is_(False)).order_by(VerificationAttempt.created_at.desc()).limit(1))
    retry_after = 0
    if last_failure:
        delay = max(challenge.cooldown_seconds, BACKOFF_SECONDS[min(max(failures - 1, 0), len(BACKOFF_SECONDS) - 1)])
        retry_after = max(0, int(delay - (datetime.now(timezone.utc) - _as_utc(last_failure.created_at)).total_seconds()))
    return {"session_id": session.id, "state": "VERIFICATION", "challenge": {"id": challenge.id, "prompt": decrypt_prompt(challenge, settings), "attempts_remaining": max(0, challenge.max_attempts - int(failures)), "retry_after_seconds": retry_after}}


def verify_session(db: Session, session: DiscoverySession, settings: Settings, *, challenge_id: str | None, answer: str) -> dict[str, object]:
    if session.status != "verification" or not session.confirmed_person_id:
        raise HTTPException(status_code=409, detail="session is not ready for verification")
    if datetime.now(timezone.utc) >= _as_utc(session.expires_at):
        session.status = "expired"
        db.commit()
        raise HTTPException(status_code=410, detail="session expired")
    challenge = db.get(VerificationChallenge, challenge_id) if challenge_id else _choose_challenge(db, session)
    if challenge is None or not challenge.active or challenge.person_id != session.confirmed_person_id:
        raise HTTPException(status_code=404, detail="verification challenge not found")
    failures = db.scalar(select(func.count(VerificationAttempt.id)).where(VerificationAttempt.session_id == session.id, VerificationAttempt.challenge_id == challenge.id, VerificationAttempt.success.is_(False))) or 0
    if failures >= challenge.max_attempts:
        session.status = "locked"
        db.commit()
        return {"session_id": session.id, "state": "LOCKED"}
    last_failure = db.scalar(select(VerificationAttempt).where(VerificationAttempt.session_id == session.id, VerificationAttempt.challenge_id == challenge.id, VerificationAttempt.success.is_(False)).order_by(VerificationAttempt.created_at.desc()).limit(1))
    if last_failure:
        delay = max(challenge.cooldown_seconds, BACKOFF_SECONDS[min(max(failures - 1, 0), len(BACKOFF_SECONDS) - 1)])
        remaining = delay - (datetime.now(timezone.utc) - _as_utc(last_failure.created_at)).total_seconds()
        if remaining > 0:
            raise HTTPException(status_code=429, detail="verification temporarily throttled", headers={"Retry-After": str(max(1, int(remaining)))} )
    submitted = answer_hmac(settings, person_id=session.confirmed_person_id, challenge_id=challenge.id, normalized_answer=normalize_answer(answer))
    digests = db.scalars(select(VerificationAnswerDigest).where(VerificationAnswerDigest.challenge_id == challenge.id, VerificationAnswerDigest.normalization_version == NORMALIZATION_VERSION)).all()
    success = any(hmac.compare_digest(submitted, digest.answer_hmac) for digest in digests)
    db.add(VerificationAttempt(session_id=session.id, challenge_id=challenge.id, success=success))
    if success:
        session.status = "verified"
        record_audit(db, actor_type="public", event_type="verification.success", target_type="session", target_id=session.id, metadata={"challenge_id": challenge.id})
        db.commit()
        from app.services.grants import asset_list

        return asset_list(db, session, settings)
    record_audit(db, actor_type="public", event_type="verification.failed", target_type="session", target_id=session.id, metadata={"challenge_id": challenge.id, "attempt_number": int(failures) + 1})
    if failures + 1 >= challenge.max_attempts:
        session.status = "locked"
        db.commit()
        return {"session_id": session.id, "state": "LOCKED"}
    db.commit()
    return verification_payload(db, session, settings)
