"""Sealed Release and Recovery Key metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SealedRelease(Base):
    __tablename__ = "sealed_releases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    version: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="building")
    integrity_snapshot_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identity_integrity_snapshots.id", ondelete="SET NULL"), nullable=True)
    recovery_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    database_snapshot_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    vault_manifest_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    oci_image_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    wheelhouse_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    recovery_wrapped_master_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    recovery_wrapped_answer_pepper_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    archive_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryKeyRecord(Base):
    __tablename__ = "recovery_key_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    verification_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
