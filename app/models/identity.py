"""Person, Discovery Question, and TraitAnswer authoring models."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Person(Base):
    __tablename__ = "people"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    slug_internal: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(24))
    display_name_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    display_name_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    avatar_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", server_default="active")
    delivery_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    trait_answers: Mapped[list["TraitAnswer"]] = relationship(back_populates="person", cascade="all, delete-orphan")


class Question(Base):
    __tablename__ = "questions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    text_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    text_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    privacy_level: Mapped[str] = mapped_column(String(32), nullable=False)
    answer_scale: Mapped[str] = mapped_column(String(32), nullable=False, default="five_point", server_default="five_point")
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    facet_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    trait_answers: Mapped[list["TraitAnswer"]] = relationship(back_populates="question", cascade="all, delete-orphan")


class TraitAnswer(Base):
    __tablename__ = "trait_answers"
    __table_args__ = (UniqueConstraint("person_id", "question_id", name="uq_trait_answers_person_question"),)

    person_id: Mapped[str] = mapped_column(String(36), ForeignKey("people.id", ondelete="CASCADE"), primary_key=True)
    question_id: Mapped[str] = mapped_column(String(36), ForeignKey("questions.id", ondelete="CASCADE"), primary_key=True)
    value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    source_note_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    source_note_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    person: Mapped[Person] = relationship(back_populates="trait_answers")
    question: Mapped[Question] = relationship(back_populates="trait_answers")

