"""Add scope_json and ai_settings_json columns to ChatThreads table.

These columns persist the query scope and AI knowledge settings for each thread,
allowing us to restore the user's context when loading a thread.

Revision ID: 007
Revises: 006
Create Date: 2026-01-04 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import NVARCHAR

# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add scope_json and ai_settings_json columns to ChatThreads table."""
    op.add_column(
        "ChatThreads",
        sa.Column("scope_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "ChatThreads",
        sa.Column("ai_settings_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Remove scope_json and ai_settings_json columns from ChatThreads table."""
    op.drop_column("ChatThreads", "ai_settings_json")
    op.drop_column("ChatThreads", "scope_json")
