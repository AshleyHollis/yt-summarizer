"""Add last_run_id column to ChatThreads table.

This column tracks the last processed run_id to prevent re-running
the agent when loading existing threads.

Revision ID: 006
Revises: 005
Create Date: 2025-01-01 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.mssql import NVARCHAR

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add last_run_id column to ChatThreads table."""
    op.add_column(
        "ChatThreads",
        sa.Column("last_run_id", NVARCHAR(100), nullable=True),
    )


def downgrade() -> None:
    """Remove last_run_id column from ChatThreads table."""
    op.drop_column("ChatThreads", "last_run_id")
