"""Per-Asset AES-GCM encryption and Vault file handling."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.asset import Asset
from app.models.identity import Person
from app.security.crypto import encrypt_secret
from app.services.metadata import decrypt_secret


ASSET_NAME_CONTEXT = b"still-alive/asset/display-name/v1"


def _asset_context(asset_id: str) -> bytes:
    return f"still-alive/asset/content/{asset_id}/v1".encode("utf-8")


def create_asset(db: Session, settings: Settings, *, person_id: str, display_name: str, mime_type: str, plaintext: bytes) -> Asset:
    person = db.get(Person, person_id)
    if person is None:
        raise HTTPException(status_code=404, detail="Person not found")
    display_name = display_name.strip()
    if not display_name or len(display_name) > 200 or "\r" in display_name or "\n" in display_name:
        raise HTTPException(status_code=400, detail="invalid asset display name")
    if not plaintext:
        raise HTTPException(status_code=400, detail="asset cannot be empty")
    if len(mime_type) > 128:
        mime_type = "application/octet-stream"
    asset_id = str(uuid4())
    name_nonce, name_ciphertext = encrypt_secret(display_name, settings.master_key_bytes, context=ASSET_NAME_CONTEXT)
    dek = secrets.token_bytes(32)
    content_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(content_nonce, plaintext, _asset_context(asset_id))
    wrap_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(settings.master_key_bytes).encrypt(wrap_nonce, dek, _asset_context(asset_id) + b"/wrap")
    relative_path = f"{asset_id}.bin"
    vault_path = (settings.vault_path / relative_path).resolve()
    vault_root = settings.vault_path.resolve()
    if vault_path.parent != vault_root:
        raise HTTPException(status_code=500, detail="invalid Vault path")
    vault_root.mkdir(parents=True, exist_ok=True)
    vault_path.write_bytes(ciphertext)
    asset = Asset(
        id=asset_id,
        person_id=person_id,
        display_name_ciphertext=name_ciphertext,
        display_name_nonce=name_nonce,
        mime_type=mime_type or "application/octet-stream",
        ciphertext_path=relative_path,
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        wrapped_dek=wrapped_dek,
        wrap_nonce=wrap_nonce,
        content_nonce=content_nonce,
        size_plain=len(plaintext),
        size_cipher=len(ciphertext),
        active=True,
    )
    db.add(asset)
    return asset


def decrypt_asset(asset: Asset, settings: Settings) -> bytes:
    vault_root = settings.vault_path.resolve()
    path = (vault_root / asset.ciphertext_path).resolve()
    if path.parent != vault_root or not path.is_file():
        raise HTTPException(status_code=404, detail="asset content not found")
    ciphertext = path.read_bytes()
    if hashlib.sha256(ciphertext).hexdigest() != asset.ciphertext_sha256:
        raise HTTPException(status_code=500, detail="asset integrity check failed")
    dek = AESGCM(settings.master_key_bytes).decrypt(asset.wrap_nonce, asset.wrapped_dek, _asset_context(asset.id) + b"/wrap")
    return AESGCM(dek).decrypt(asset.content_nonce, ciphertext, _asset_context(asset.id))


def asset_display_name(asset: Asset, settings: Settings) -> str:
    return decrypt_secret(asset.display_name_ciphertext, asset.display_name_nonce, settings.master_key_bytes, context=ASSET_NAME_CONTEXT)
