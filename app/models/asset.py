"""Encrypted Vault Asset metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    person_id: Mapped[str] = mapped_column(String(36), ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)
    display_name_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    display_name_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    ciphertext_path: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size_plain: Mapped[int] = mapped_column(Integer, nullable=False)
    size_cipher: Mapped[int] = mapped_column(Integer, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
