"""Add Identity Integrity snapshots, pair metrics, and clusters."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0004_identity_integrity"
down_revision: str | None = "0003_identity_authoring"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_integrity_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("algorithm_version", sa.String(length=64), nullable=False),
        sa.Column("noise_profile_version", sa.String(length=64), nullable=False),
        sa.Column("active_person_count", sa.Integer(), nullable=False),
        sa.Column("active_question_count", sa.Integer(), nullable=False),
        sa.Column("blocking_pair_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("warning_pair_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("cluster_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("worst_confusion_rate", sa.Float(), server_default="0", nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "identity_pair_metrics",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("person_a_id", sa.String(length=36), nullable=False),
        sa.Column("person_b_id", sa.String(length=36), nullable=False),
        sa.Column("trait_similarity", sa.Float(), nullable=False),
        sa.Column("strong_discriminator_count", sa.Integer(), nullable=False),
        sa.Column("distinct_facet_count", sa.Integer(), nullable=False),
        sa.Column("confusion_a_to_b", sa.Float(), nullable=False),
        sa.Column("confusion_b_to_a", sa.Float(), nullable=False),
        sa.Column("mean_score_margin", sa.Float(), nullable=False),
        sa.Column("p05_score_margin", sa.Float(), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["identity_integrity_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_id", "person_a_id", "person_b_id", name="uq_identity_pair_snapshot_people"),
    )
    op.create_index("ix_identity_pair_metrics_snapshot_id", "identity_pair_metrics", ["snapshot_id"], unique=False)
    op.create_table(
        "identity_clusters",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("cluster_id", sa.String(length=64), nullable=False),
        sa.Column("member_person_ids", sa.Text(), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("worst_pair", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["identity_integrity_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_id", "cluster_id", name="uq_identity_cluster_snapshot_cluster"),
    )
    op.create_index("ix_identity_clusters_snapshot_id", "identity_clusters", ["snapshot_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_identity_clusters_snapshot_id", table_name="identity_clusters")
    op.drop_table("identity_clusters")
    op.drop_index("ix_identity_pair_metrics_snapshot_id", table_name="identity_pair_metrics")
    op.drop_table("identity_pair_metrics")
    op.drop_table("identity_integrity_snapshots")
