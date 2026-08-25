"""Per-person public delivery presentation settings."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeliveryProfile(Base):
    __tablename__ = "delivery_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    person_id: Mapped[str] = mapped_column(String(36), ForeignKey("people.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    theme: Mapped[str] = mapped_column(String(32), nullable=False, default="quiet", server_default="quiet")
    content_type: Mapped[str] = mapped_column(String(32), nullable=False, default="letter", server_default="letter")
    cover_title_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    cover_title_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    opening_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    opening_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    signature_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    signature_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
