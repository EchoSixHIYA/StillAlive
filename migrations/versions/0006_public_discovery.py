"""Add public Discovery Session and answer persistence."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_public_discovery"
down_revision: str | None = "0005_identity_integrity_static_metrics"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "discovery_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=24), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("guessed_person_id", sa.String(length=36), nullable=True),
        sa.Column("confirmed_person_id", sa.String(length=36), nullable=True),
        sa.Column("question_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_guess_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rejected_person_ids", sa.Text(), server_default="[]", nullable=False),
        sa.Column("ip_hash", sa.LargeBinary(), nullable=True),
        sa.Column("ua_hash", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(["guessed_person_id"], ["people.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["confirmed_person_id"], ["people.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_discovery_sessions_status_expires_at", "discovery_sessions", ["status", "expires_at"], unique=False)
    op.create_table(
        "discovery_answers",
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("question_id", sa.String(length=36), nullable=False),
        sa.Column("normalized_value", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["discovery_sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["question_id"], ["questions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("session_id", "question_id"),
        sa.UniqueConstraint("session_id", "question_id", name="uq_discovery_answers_session_question"),
    )


def downgrade() -> None:
    op.drop_table("discovery_answers")
    op.drop_index("ix_discovery_sessions_status_expires_at", table_name="discovery_sessions")
    op.drop_table("discovery_sessions")
