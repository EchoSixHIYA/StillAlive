"""Public Discovery Session persistence models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DiscoverySession(Base):
    __tablename__ = "discovery_sessions"
    __table_args__ = (Index("ix_discovery_sessions_status_expires_at", "status", "expires_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", server_default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    guessed_person_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("people.id", ondelete="SET NULL"), nullable=True)
    confirmed_person_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("people.id", ondelete="SET NULL"), nullable=True)
    question_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    failed_guess_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    rejected_person_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]", server_default="[]")
    ip_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ua_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    def rejected_ids(self) -> set[str]:
        try:
            values = json.loads(self.rejected_person_ids)
        except (TypeError, json.JSONDecodeError):
            return set()
        return {str(value) for value in values}

    def set_rejected_ids(self, values: set[str]) -> None:
        self.rejected_person_ids = json.dumps(sorted(values))


class DiscoveryAnswer(Base):
    __tablename__ = "discovery_answers"
    __table_args__ = (UniqueConstraint("session_id", "question_id", name="uq_discovery_answers_session_question"),)

    session_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_sessions.id", ondelete="CASCADE"), primary_key=True)
    question_id: Mapped[str] = mapped_column(String(36), ForeignKey("questions.id", ondelete="CASCADE"), primary_key=True)
    normalized_value: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
