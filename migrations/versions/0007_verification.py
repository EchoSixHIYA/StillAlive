"""Add verification challenges, digests, and attempts."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0007_verification"
down_revision: str | None = "0006_public_discovery"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "verification_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("person_id", sa.String(length=36), nullable=False),
        sa.Column("prompt_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("prompt_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="5", nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), server_default="2", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["person_id"], ["people.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_verification_challenges_person_id", "verification_challenges", ["person_id"], unique=False)
    op.create_table(
        "verification_answer_digests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("challenge_id", sa.String(length=36), nullable=False),
        sa.Column("normalization_version", sa.String(length=16), nullable=False),
        sa.Column("answer_hmac", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["challenge_id"], ["verification_challenges.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_verification_answer_digests_challenge_id", "verification_answer_digests", ["challenge_id"], unique=False)
    op.create_table(
        "verification_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("challenge_id", sa.String(length=36), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["challenge_id"], ["verification_challenges.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["discovery_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", "challenge_id", "created_at", name="uq_verification_attempt_event"),
    )
    op.create_index("ix_verification_attempts_session_id", "verification_attempts", ["session_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_verification_attempts_session_id", table_name="verification_attempts")
    op.drop_table("verification_attempts")
    op.drop_index("ix_verification_answer_digests_challenge_id", table_name="verification_answer_digests")
    op.drop_table("verification_answer_digests")
    op.drop_index("ix_verification_challenges_person_id", table_name="verification_challenges")
    op.drop_table("verification_challenges")
