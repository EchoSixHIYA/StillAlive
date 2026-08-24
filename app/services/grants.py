"""DownloadGrant creation, validation, and atomic one-time consumption."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.asset import Asset
from app.models.discovery import DiscoverySession
from app.models.grant import DownloadGrant
from app.models.identity import Person
from app.services.assets import asset_display_name, decrypt_asset
from app.services.audit import record_audit


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _verified_asset(db: Session, session: DiscoverySession, asset_id: str) -> tuple[Person, Asset]:
    if session.status != "verified" or not session.confirmed_person_id:
        raise HTTPException(status_code=403, detail="verified session required")
    person = db.get(Person, session.confirmed_person_id)
    asset = db.get(Asset, asset_id)
    if person is None or person.status != "active" or asset is None or not asset.active or asset.person_id != person.id:
        raise HTTPException(status_code=404, detail="asset not found")
    return person, asset


def asset_list(db: Session, session: DiscoverySession, settings: Settings) -> dict[str, object]:
    if session.status != "verified" or not session.confirmed_person_id:
        raise HTTPException(status_code=403, detail="verified session required")
    person = db.get(Person, session.confirmed_person_id)
    if person is None or person.status != "active":
        raise HTTPException(status_code=404, detail="person not found")
    assets = db.scalars(select(Asset).where(Asset.person_id == person.id, Asset.active.is_(True)).order_by(Asset.created_at.desc())).all()
    return {"session_id": session.id, "state": "VERIFIED", "assets": [{"id": asset.id, "display_name": asset_display_name(asset, settings), "mime_type": asset.mime_type, "size": asset.size_plain} for asset in assets]}


def create_grant(db: Session, session: DiscoverySession, settings: Settings, *, asset_id: str) -> tuple[str, DownloadGrant]:
    person, asset = _verified_asset(db, session, asset_id)
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    grant = DownloadGrant(token_digest=_token_digest(token), session_id=session.id, person_id=person.id, asset_id=asset.id, expires_at=now + timedelta(seconds=settings.download_grant_ttl_seconds), downloads_remaining=settings.download_grant_max_uses)
    db.add(grant)
    db.flush()
    record_audit(db, actor_type="public", event_type="grant.created", target_type="asset", target_id=asset.id, metadata={"session_id": session.id, "person_id": person.id, "ttl_seconds": settings.download_grant_ttl_seconds})
    return token, grant


def consume_grant(db: Session, settings: Settings, token: str) -> tuple[Asset, Person, bytes, str]:
    if not token or len(token) > 256:
        raise HTTPException(status_code=404, detail="download not found")
    grant = db.scalar(select(DownloadGrant).where(DownloadGrant.token_digest == _token_digest(token)))
    if grant is None:
        raise HTTPException(status_code=404, detail="download not found")
    now = datetime.now(timezone.utc)
    if grant.revoked_at is not None or grant.downloads_remaining <= 0 or now >= _as_utc(grant.expires_at):
        raise HTTPException(status_code=410, detail="download grant expired or consumed")
    session = db.get(DiscoverySession, grant.session_id)
    person = db.get(Person, grant.person_id)
    asset = db.get(Asset, grant.asset_id)
    if session is None or person is None or asset is None or session.status != "verified" or session.confirmed_person_id != person.id or person.status != "active" or not asset.active or asset.person_id != person.id:
        raise HTTPException(status_code=403, detail="download grant is no longer valid")
    result = db.execute(update(DownloadGrant).where(DownloadGrant.id == grant.id, DownloadGrant.downloads_remaining > 0, DownloadGrant.revoked_at.is_(None)).values(downloads_remaining=DownloadGrant.downloads_remaining - 1))
    if result.rowcount != 1:
        raise HTTPException(status_code=410, detail="download grant already consumed")
    plaintext = decrypt_asset(asset, settings)
    record_audit(db, actor_type="public", event_type="grant.consumed", target_type="grant", target_id=grant.id, metadata={"session_id": grant.session_id, "asset_id": grant.asset_id})
    db.commit()
    return asset, person, plaintext, asset_display_name(asset, settings)


def content_disposition(display_name: str) -> str:
    cleaned = display_name.replace("\r", "").replace("\n", "").replace("/", "_").replace("\\", "_").strip() or "download"
    return f"attachment; filename*=UTF-8''{quote(cleaned)}"
