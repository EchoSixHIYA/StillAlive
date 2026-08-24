"""Recovery Key verification and AEAD wrapping for offline restoration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.release import RecoveryKeyRecord


RECOVERY_VERSION = "v1"
RECOVERY_CONTEXT = b"still-alive/recovery-key/v1"


def normalize_recovery_key(value: str) -> str:
    return "".join(value.strip().split())


def recovery_digest(settings: Settings, recovery_key: str) -> str:
    key = normalize_recovery_key(recovery_key).encode("utf-8")
    return hmac.new(settings.master_key_bytes, key, hashlib.sha256).hexdigest()


def active_recovery_record(db: Session) -> RecoveryKeyRecord | None:
    return db.scalar(select(RecoveryKeyRecord).where(RecoveryKeyRecord.rotated_at.is_(None)).order_by(RecoveryKeyRecord.created_at.desc()).limit(1))


def verify_recovery_key(db: Session, settings: Settings, recovery_key: str) -> RecoveryKeyRecord:
    value = normalize_recovery_key(recovery_key)
    if len(value) < 32 or len(value) > 256:
        raise HTTPException(status_code=422, detail="invalid recovery key")
    record = active_recovery_record(db)
    if record is None or not hmac.compare_digest(record.verification_digest, recovery_digest(settings, value)):
        raise HTTPException(status_code=403, detail="recovery key verification failed")
    return record


def create_recovery_record(db: Session, settings: Settings, recovery_key: str) -> RecoveryKeyRecord:
    value = normalize_recovery_key(recovery_key)
    if len(value) < 32 or len(value) > 256:
        raise HTTPException(status_code=422, detail="recovery key must contain 32-256 non-space characters")
    now = datetime.now(timezone.utc)
    previous = active_recovery_record(db)
    if previous is not None:
        previous.rotated_at = now
    record = RecoveryKeyRecord(key_id=f"rk-{secrets.token_urlsafe(12)}", verification_digest=recovery_digest(settings, value))
    db.add(record)
    db.flush()
    return record


def _kek(recovery_key: str, *, purpose: bytes) -> bytes:
    normalized = normalize_recovery_key(recovery_key).encode("utf-8")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=RECOVERY_CONTEXT + b"/" + purpose).derive(normalized)


def wrap_recovery_secret(secret: bytes, recovery_key: str, *, purpose: str) -> bytes:
    purpose_bytes = purpose.encode("ascii")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_kek(recovery_key, purpose=purpose_bytes)).encrypt(nonce, secret, RECOVERY_CONTEXT + b"/" + purpose_bytes)
    return json.dumps({"version": RECOVERY_VERSION, "purpose": purpose, "nonce": base64.b64encode(nonce).decode("ascii"), "ciphertext": base64.b64encode(ciphertext).decode("ascii")}, sort_keys=True).encode("utf-8")


def unwrap_recovery_secret(payload: bytes, recovery_key: str, *, purpose: str) -> bytes:
    try:
        data = json.loads(payload.decode("utf-8"))
        if data["version"] != RECOVERY_VERSION or data["purpose"] != purpose:
            raise ValueError
        nonce = base64.b64decode(data["nonce"], validate=True)
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        return AESGCM(_kek(recovery_key, purpose=purpose.encode("ascii"))).decrypt(nonce, ciphertext, RECOVERY_CONTEXT + b"/" + purpose.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid recovery secret wrapper") from exc
