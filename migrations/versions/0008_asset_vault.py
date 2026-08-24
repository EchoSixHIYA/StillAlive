"""Add encrypted Vault Asset metadata."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0008_asset_vault"
down_revision: str | None = "0007_verification"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("person_id", sa.String(length=36), nullable=False),
        sa.Column("display_name_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("display_name_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("mime_type", sa.String(length=128), nullable=False),
        sa.Column("ciphertext_path", sa.String(length=256), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("wrap_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("content_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("size_plain", sa.Integer(), nullable=False),
        sa.Column("size_cipher", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["person_id"], ["people.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ciphertext_path"),
    )
    op.create_index("ix_assets_person_id", "assets", ["person_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_assets_person_id", table_name="assets")
    op.drop_table("assets")
