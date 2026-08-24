"""Persisted Identity Integrity snapshots and derived risk structures."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IdentityIntegritySnapshot(Base):
    __tablename__ = "identity_integrity_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False)
    noise_profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    active_person_count: Mapped[int] = mapped_column(Integer, nullable=False)
    active_question_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocking_pair_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    warning_pair_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    cluster_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    worst_confusion_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityPairMetric(Base):
    __tablename__ = "identity_pair_metrics"
    __table_args__ = (UniqueConstraint("snapshot_id", "person_a_id", "person_b_id", name="uq_identity_pair_snapshot_people"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    snapshot_id: Mapped[str] = mapped_column(String(36), ForeignKey("identity_integrity_snapshots.id", ondelete="CASCADE"), nullable=False, index=True)
    person_a_id: Mapped[str] = mapped_column(String(36), nullable=False)
    person_b_id: Mapped[str] = mapped_column(String(36), nullable=False)
    trait_similarity: Mapped[float] = mapped_column(Float, nullable=False)
    strong_discriminator_count: Mapped[int] = mapped_column(Integer, nullable=False)
    distinct_facet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    common_question_count: Mapped[int] = mapped_column(Integer, nullable=False)
    theoretical_max_score_separation: Mapped[float] = mapped_column(Float, nullable=False)
    confusion_a_to_b: Mapped[float] = mapped_column(Float, nullable=False)
    confusion_b_to_a: Mapped[float] = mapped_column(Float, nullable=False)
    mean_score_margin: Mapped[float] = mapped_column(Float, nullable=False)
    p05_score_margin: Mapped[float] = mapped_column(Float, nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)


class IdentityCluster(Base):
    __tablename__ = "identity_clusters"
    __table_args__ = (UniqueConstraint("snapshot_id", "cluster_id", name="uq_identity_cluster_snapshot_cluster"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    snapshot_id: Mapped[str] = mapped_column(String(36), ForeignKey("identity_integrity_snapshots.id", ondelete="CASCADE"), nullable=False, index=True)
    cluster_id: Mapped[str] = mapped_column(String(64), nullable=False)
    member_person_ids: Mapped[str] = mapped_column(Text, nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    worst_pair: Mapped[str] = mapped_column(String(128), nullable=False)
