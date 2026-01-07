"""Add last_run_id column to ChatThreads table.

This column tracks the last processed run_id to prevent re-running
the agent when loading existing threads.

Revision ID: 006
Revises: 005
Create Date: 2025-01-01 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import NVARCHAR

# revision identifiers, used by Alembic.
revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add last_run_id column to ChatThreads table."""
    op.add_column(
        "ChatThreads",
        sa.Column("last_run_id", NVARCHAR(100), nullable=True),
    )


def downgrade() -> None:
    """Remove last_run_id column from ChatThreads table."""
    op.drop_column("ChatThreads", "last_run_id")
