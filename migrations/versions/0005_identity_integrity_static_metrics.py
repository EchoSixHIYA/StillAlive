"""Add static coverage and theoretical separation metrics to identity pairs."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0005_identity_integrity_static_metrics"
down_revision: str | None = "0004_identity_integrity"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("identity_pair_metrics", sa.Column("common_question_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column("identity_pair_metrics", sa.Column("theoretical_max_score_separation", sa.Float(), server_default="0", nullable=False))


def downgrade() -> None:
    op.drop_column("identity_pair_metrics", "theoretical_max_score_separation")
    op.drop_column("identity_pair_metrics", "common_question_count")
