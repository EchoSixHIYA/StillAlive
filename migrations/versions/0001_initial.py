"""Initial migration baseline.

The domain tables are intentionally introduced in later implementation
phases. This revision establishes a clean Alembic-controlled database for
Phase 0 and allows readiness checks to distinguish migrated databases.
"""

from collections.abc import Sequence


revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

