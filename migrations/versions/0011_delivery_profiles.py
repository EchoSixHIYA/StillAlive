"""Add per-person public delivery presentation settings."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0011_delivery_profiles"
down_revision: str | None = "0010_sealed_release"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "delivery_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("person_id", sa.String(length=36), nullable=False),
        sa.Column("theme", sa.String(length=32), server_default="quiet", nullable=False),
        sa.Column("content_type", sa.String(length=32), server_default="letter", nullable=False),
        sa.Column("cover_title_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("cover_title_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("opening_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("opening_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("signature_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("signature_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["person_id"], ["people.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("person_id"),
    )
    op.create_index("ix_delivery_profiles_person_id", "delivery_profiles", ["person_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_delivery_profiles_person_id", table_name="delivery_profiles")
    op.drop_table("delivery_profiles")
