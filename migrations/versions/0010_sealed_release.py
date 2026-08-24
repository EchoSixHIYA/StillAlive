"""Add Sealed Release and Recovery Key metadata."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0010_sealed_release"
down_revision: str | None = "0009_download_grants"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sealed_releases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("integrity_snapshot_id", sa.String(length=36), nullable=True),
        sa.Column("recovery_key_id", sa.String(length=128), nullable=True),
        sa.Column("database_snapshot_path", sa.String(length=512), nullable=True),
        sa.Column("vault_manifest_path", sa.String(length=512), nullable=True),
        sa.Column("oci_image_path", sa.String(length=512), nullable=True),
        sa.Column("wheelhouse_path", sa.String(length=512), nullable=True),
        sa.Column("recovery_wrapped_master_key_path", sa.String(length=512), nullable=True),
        sa.Column("recovery_wrapped_answer_pepper_path", sa.String(length=512), nullable=True),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("archive_path", sa.String(length=512), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["integrity_snapshot_id"], ["identity_integrity_snapshots.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version"),
    )
    op.create_table(
        "recovery_key_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("verification_digest", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_id"),
    )


def downgrade() -> None:
    op.drop_table("recovery_key_records")
    op.drop_table("sealed_releases")
