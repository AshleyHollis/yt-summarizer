"""Initial schema - Channels and Videos tables.

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER, NVARCHAR

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Channels and Videos tables."""
    # Channels table
    op.create_table(
        "Channels",
        sa.Column(
            "channel_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "youtube_channel_id",
            NVARCHAR(50),
            nullable=False,
            unique=True,
        ),
        sa.Column("name", NVARCHAR(200), nullable=False),
        sa.Column("description", NVARCHAR(None), nullable=True),
        sa.Column("thumbnail_url", NVARCHAR(500), nullable=True),
        sa.Column("video_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
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
    op.create_index(
        "ix_channels_youtube_id",
        "Channels",
        ["youtube_channel_id"],
    )

    # Videos table
    op.create_table(
        "Videos",
        sa.Column(
            "video_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "youtube_video_id",
            NVARCHAR(20),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "channel_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Channels.channel_id"),
            nullable=False,
        ),
        sa.Column("title", NVARCHAR(500), nullable=False),
        sa.Column("description", NVARCHAR(None), nullable=True),
        sa.Column("duration", sa.Integer(), nullable=False),
        sa.Column("publish_date", sa.DateTime(), nullable=False),
        sa.Column("thumbnail_url", NVARCHAR(500), nullable=True),
        sa.Column(
            "processing_status",
            NVARCHAR(50),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_message", NVARCHAR(None), nullable=True),
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
    op.create_index("ix_videos_youtube_id", "Videos", ["youtube_video_id"])
    op.create_index("ix_videos_channel", "Videos", ["channel_id"])
    op.create_index("ix_videos_publish_date", "Videos", ["publish_date"])
    op.create_index("ix_videos_status", "Videos", ["processing_status"])


def downgrade() -> None:
    """Drop Channels and Videos tables."""
    op.drop_table("Videos")
    op.drop_table("Channels")
