"""Add next_retry_at column to Jobs table.

Revision ID: 008
Revises: 007
Create Date: 2026-01-05

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add next_retry_at column to Jobs table."""
    op.add_column("Jobs", sa.Column("next_retry_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Remove next_retry_at column from Jobs table."""
    op.drop_column("Jobs", "next_retry_at")
