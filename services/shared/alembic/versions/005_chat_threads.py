"""ChatThreads table for copilot conversation persistence.

Revision ID: 005
Revises: 004
Create Date: 2025-01-01 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.mssql import NVARCHAR

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create ChatThreads table for storing copilot conversation history."""
    op.create_table(
        "ChatThreads",
        # Thread ID - matches CopilotKit's threadId
        sa.Column("thread_id", NVARCHAR(100), primary_key=True),
        # Optional title for the thread
        sa.Column("title", NVARCHAR(200), nullable=True),
        # JSON-serialized messages array
        sa.Column("messages_json", NVARCHAR(None), nullable=False, server_default="[]"),
        # JSON-serialized agent state
        sa.Column("state_json", NVARCHAR(None), nullable=True),
        # Agent name this thread is associated with
        sa.Column("agent_name", NVARCHAR(100), nullable=False, server_default="'yt-summarizer'"),
        # Message count for quick access
        sa.Column("message_count", sa.Integer(), nullable=False, server_default="0"),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
    )

    # Indexes for common queries
    op.create_index("ix_chat_threads_agent", "ChatThreads", ["agent_name"])
    op.create_index("ix_chat_threads_updated", "ChatThreads", ["updated_at"])


def downgrade() -> None:
    """Drop ChatThreads table."""
    op.drop_index("ix_chat_threads_updated", table_name="ChatThreads")
    op.drop_index("ix_chat_threads_agent", table_name="ChatThreads")
    op.drop_table("ChatThreads")
