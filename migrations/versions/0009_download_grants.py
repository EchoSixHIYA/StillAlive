"""Add short-lived single-use DownloadGrant records."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0009_download_grants"
down_revision: str | None = "0008_asset_vault"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "download_grants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("person_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("downloads_remaining", sa.Integer(), server_default="1", nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["person_id"], ["people.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["discovery_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_index("ix_download_grants_session_id", "download_grants", ["session_id"], unique=False)
    op.create_index("ix_download_grants_person_id", "download_grants", ["person_id"], unique=False)
    op.create_index("ix_download_grants_asset_id", "download_grants", ["asset_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_download_grants_asset_id", table_name="download_grants")
    op.drop_index("ix_download_grants_person_id", table_name="download_grants")
    op.drop_index("ix_download_grants_session_id", table_name="download_grants")
    op.drop_table("download_grants")
