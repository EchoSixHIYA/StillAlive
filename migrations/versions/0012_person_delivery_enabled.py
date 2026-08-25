"""Add an explicit reversible delivery switch per person."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0012_person_delivery_enabled"
down_revision: str | None = "0011_delivery_profiles"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("people", sa.Column("delivery_enabled", sa.Boolean(), server_default="1", nullable=False))


def downgrade() -> None:
    op.drop_column("people", "delivery_enabled")
