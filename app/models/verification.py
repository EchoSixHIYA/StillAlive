"""Verification challenge and attempt persistence models."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VerificationChallenge(Base):
    __tablename__ = "verification_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    person_id: Mapped[str] = mapped_column(String(36), ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)
    prompt_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    prompt_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5, server_default="5")
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=2, server_default="2")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class VerificationAnswerDigest(Base):
    __tablename__ = "verification_answer_digests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    challenge_id: Mapped[str] = mapped_column(String(36), ForeignKey("verification_challenges.id", ondelete="CASCADE"), nullable=False, index=True)
    normalization_version: Mapped[str] = mapped_column(String(16), nullable=False)
    answer_hmac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class VerificationAttempt(Base):
    __tablename__ = "verification_attempts"
    __table_args__ = (UniqueConstraint("session_id", "challenge_id", "created_at", name="uq_verification_attempt_event"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    session_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    challenge_id: Mapped[str] = mapped_column(String(36), ForeignKey("verification_challenges.id", ondelete="CASCADE"), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
