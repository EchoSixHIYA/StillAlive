"""Explicit lifecycle operations for authored delivery data.

Normal UI actions are reversible (撤销交付/归档).  Permanent deletion is
separate, requires a confirmation token, and keeps an audit event without
keeping the deleted content or answer material.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.asset import Asset
from app.models.discovery import DiscoverySession
from app.models.delivery import DeliveryProfile
from app.models.grant import DownloadGrant
from app.models.identity import Person, TraitAnswer
from app.models.verification import VerificationAnswerDigest, VerificationAttempt, VerificationChallenge
from app.services.audit import record_audit
from app.services.identity_integrity import mark_latest_stale


def _vault_path(settings: Settings, relative_path: str) -> Path:
    root = settings.vault_path.resolve()
    path = (root / relative_path).resolve()
    if path.parent != root:
        raise RuntimeError("invalid Vault path")
    return path


def _remove_vault_files(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # The database row is already gone, so the content is no longer
            # addressable. Keep the audit trail and let an operator clean up
            # an orphan file if the filesystem is temporarily unavailable.
            continue


def revoke_person_delivery(db: Session, *, person_id: str, actor_id: str) -> dict[str, int]:
    """Stop all public delivery while retaining authored data for later restore."""
    person = db.get(Person, person_id)
    if person is None:
        raise LookupError("Person not found")
    person.delivery_enabled = False
    sessions = db.scalars(
        select(DiscoverySession).where(
            (DiscoverySession.guessed_person_id == person_id) | (DiscoverySession.confirmed_person_id == person_id),
            DiscoverySession.status.in_({"active", "guess", "verification", "verified"}),
        )
    ).all()
    for session in sessions:
        session.status = "expired"
    now = datetime.now(timezone.utc)
    grants = db.execute(
        update(DownloadGrant)
        .where(DownloadGrant.person_id == person_id, DownloadGrant.revoked_at.is_(None))
        .values(revoked_at=now, downloads_remaining=0)
    )
    record_audit(
        db,
        actor_type="admin",
        event_type="person.delivery_revoked",
        actor_id=actor_id,
        target_type="person",
        target_id=person_id,
        metadata={"session_count": len(sessions), "grant_count": int(grants.rowcount or 0), "data_retained": True},
    )
    db.commit()
    return {"session_count": len(sessions), "grant_count": int(grants.rowcount or 0)}


def restore_person_delivery(db: Session, *, person_id: str, actor_id: str) -> None:
    person = db.get(Person, person_id)
    if person is None:
        raise LookupError("Person not found")
    person.delivery_enabled = True
    record_audit(db, actor_type="admin", event_type="person.delivery_restored", actor_id=actor_id, target_type="person", target_id=person_id, metadata={"data_retained": True})
    db.commit()


def permanently_delete_person(db: Session, settings: Settings, *, person_id: str, actor_id: str) -> None:
    person = db.get(Person, person_id)
    if person is None:
        raise LookupError("Person not found")
    challenges = db.scalars(select(VerificationChallenge).where(VerificationChallenge.person_id == person_id)).all()
    challenge_ids = [challenge.id for challenge in challenges]
    assets = db.scalars(select(Asset).where(Asset.person_id == person_id)).all()
    paths = [_vault_path(settings, asset.ciphertext_path) for asset in assets]
    mark_latest_stale(db, actor_type="admin", actor_id=actor_id, reason="person.permanently_deleted")
    record_audit(
        db,
        actor_type="admin",
        event_type="person.permanently_deleted",
        actor_id=actor_id,
        target_type="person",
        target_id=person_id,
        metadata={"asset_count": len(assets), "challenge_count": len(challenges), "audit_retained": True},
    )
    db.execute(update(DiscoverySession).where(DiscoverySession.guessed_person_id == person_id).values(guessed_person_id=None))
    db.execute(update(DiscoverySession).where(DiscoverySession.confirmed_person_id == person_id).values(confirmed_person_id=None, status="expired"))
    if challenge_ids:
        db.execute(delete(VerificationAttempt).where(VerificationAttempt.challenge_id.in_(challenge_ids)))
        db.execute(delete(VerificationAnswerDigest).where(VerificationAnswerDigest.challenge_id.in_(challenge_ids)))
        db.execute(delete(VerificationChallenge).where(VerificationChallenge.id.in_(challenge_ids)))
    db.execute(delete(DownloadGrant).where(DownloadGrant.person_id == person_id))
    db.execute(delete(DeliveryProfile).where(DeliveryProfile.person_id == person_id))
    db.execute(delete(Asset).where(Asset.person_id == person_id))
    db.execute(delete(TraitAnswer).where(TraitAnswer.person_id == person_id))
    db.execute(delete(Person).where(Person.id == person_id))
    db.commit()
    _remove_vault_files(paths)


def permanently_delete_asset(db: Session, settings: Settings, *, person_id: str, asset_id: str, actor_id: str) -> None:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.person_id != person_id:
        raise LookupError("Asset not found")
    path = _vault_path(settings, asset.ciphertext_path)
    record_audit(db, actor_type="admin", event_type="asset.permanently_deleted", actor_id=actor_id, target_type="asset", target_id=asset_id, metadata={"person_id": person_id, "audit_retained": True})
    db.execute(delete(DownloadGrant).where(DownloadGrant.asset_id == asset_id))
    db.delete(asset)
    db.commit()
    _remove_vault_files([path])


def permanently_delete_challenge(db: Session, *, person_id: str, challenge_id: str, actor_id: str) -> None:
    challenge = db.get(VerificationChallenge, challenge_id)
    if challenge is None or challenge.person_id != person_id:
        raise LookupError("Verification challenge not found")
    record_audit(db, actor_type="admin", event_type="challenge.permanently_deleted", actor_id=actor_id, target_type="challenge", target_id=challenge_id, metadata={"person_id": person_id, "audit_retained": True})
    db.execute(delete(VerificationAttempt).where(VerificationAttempt.challenge_id == challenge_id))
    db.execute(delete(VerificationAnswerDigest).where(VerificationAnswerDigest.challenge_id == challenge_id))
    db.delete(challenge)
    db.commit()
