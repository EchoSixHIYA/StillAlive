"""Encrypted, per-person presentation settings for public delivery."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.delivery import DeliveryProfile
from app.security.crypto import decrypt_secret, encrypt_secret


DELIVERY_THEMES = {"quiet", "warm", "midnight"}
DELIVERY_CONTENT_TYPES = {"letter", "photos", "video", "mixed"}
DELIVERY_CONTENT_TYPE_LABELS = {"letter": "信件", "photos": "照片", "video": "视频", "mixed": "混合内容"}
_COVER_CONTEXT = b"still-alive/delivery/cover-title/v1"
_OPENING_CONTEXT = b"still-alive/delivery/opening/v1"
_SIGNATURE_CONTEXT = b"still-alive/delivery/signature/v1"


def _encrypted(value: str, settings: Settings, context: bytes) -> tuple[bytes | None, bytes | None]:
    value = value.strip()
    if not value:
        return None, None
    nonce, ciphertext = encrypt_secret(value, settings.master_key_bytes, context=context)
    return nonce, ciphertext


def _decrypted(ciphertext: bytes | None, nonce: bytes | None, settings: Settings, context: bytes, fallback: str) -> str:
    if not ciphertext or not nonce:
        return fallback
    return decrypt_secret(ciphertext, nonce, settings.master_key_bytes, context=context)


def delivery_profile_values(profile: DeliveryProfile | None, settings: Settings) -> dict[str, str]:
    if profile is None:
        return {"theme": "quiet", "content_type": "letter", "content_type_label": "信件", "cover_title": "一份只属于你的内容", "opening": "如果你正在看到这段话，说明这份内容已经为你打开。", "signature": "Still Alive"}
    return {
        "theme": profile.theme,
        "content_type": profile.content_type,
        "content_type_label": DELIVERY_CONTENT_TYPE_LABELS.get(profile.content_type, "内容"),
        "cover_title": _decrypted(profile.cover_title_ciphertext, profile.cover_title_nonce, settings, _COVER_CONTEXT, "一份只属于你的内容"),
        "opening": _decrypted(profile.opening_ciphertext, profile.opening_nonce, settings, _OPENING_CONTEXT, "如果你正在看到这段话，说明这份内容已经为你打开。"),
        "signature": _decrypted(profile.signature_ciphertext, profile.signature_nonce, settings, _SIGNATURE_CONTEXT, "Still Alive"),
    }


def save_delivery_profile(
    db: Session,
    settings: Settings,
    *,
    person_id: str,
    theme: str,
    content_type: str,
    cover_title: str,
    opening: str,
    signature: str,
) -> DeliveryProfile:
    theme = theme.strip()
    content_type = content_type.strip()
    if theme not in DELIVERY_THEMES:
        raise ValueError("invalid delivery theme")
    if content_type not in DELIVERY_CONTENT_TYPES:
        raise ValueError("invalid delivery content type")
    if len(cover_title.strip()) > 200 or len(opening.strip()) > 2000 or len(signature.strip()) > 200:
        raise ValueError("delivery text is too long")
    profile = db.scalar(select(DeliveryProfile).where(DeliveryProfile.person_id == person_id))
    if profile is None:
        profile = DeliveryProfile(person_id=person_id)
        db.add(profile)
    profile.theme = theme
    profile.content_type = content_type
    profile.cover_title_nonce, profile.cover_title_ciphertext = _encrypted(cover_title, settings, _COVER_CONTEXT)
    profile.opening_nonce, profile.opening_ciphertext = _encrypted(opening, settings, _OPENING_CONTEXT)
    profile.signature_nonce, profile.signature_ciphertext = _encrypted(signature, settings, _SIGNATURE_CONTEXT)
    return profile
