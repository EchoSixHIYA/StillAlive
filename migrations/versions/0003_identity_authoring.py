"""Add Person, Question, and TraitAnswer authoring tables."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003_identity_authoring"
down_revision: str | None = "0002_admin_auth"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "people",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug_internal", sa.String(length=64), nullable=False),
        sa.Column("display_name_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("display_name_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("avatar_asset_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug_internal"),
    )
    op.create_table(
        "questions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("text_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("text_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("privacy_level", sa.String(length=32), nullable=False),
        sa.Column("answer_scale", sa.String(length=32), server_default="five_point", nullable=False),
        sa.Column("weight", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("facet_tag", sa.String(length=64), nullable=True),
        sa.Column("active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "trait_answers",
        sa.Column("person_id", sa.String(length=36), nullable=False),
        sa.Column("question_id", sa.String(length=36), nullable=False),
        sa.Column("value", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("source_note_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("source_note_nonce", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(["person_id"], ["people.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["question_id"], ["questions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("person_id", "question_id"),
        sa.UniqueConstraint("person_id", "question_id", name="uq_trait_answers_person_question"),
    )


def downgrade() -> None:
    op.drop_table("trait_answers")
    op.drop_table("questions")
    op.drop_table("people")

