"""Batches, BatchItems, and Jobs tables.

Revision ID: 002
Revises: 001
Create Date: 2025-01-01 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER, NVARCHAR

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Batches, BatchItems, and Jobs tables."""
    # Batches table
    op.create_table(
        "Batches",
        sa.Column(
            "batch_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "channel_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Channels.channel_id"),
            nullable=True,
        ),
        sa.Column("name", NVARCHAR(200), nullable=True),
        sa.Column("total_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pending_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("running_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("succeeded_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )

    # BatchItems table
    op.create_table(
        "BatchItems",
        sa.Column(
            "batch_item_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "batch_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Batches.batch_id"),
            nullable=False,
        ),
        sa.Column(
            "video_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Videos.video_id"),
            nullable=False,
        ),
        sa.Column(
            "status",
            NVARCHAR(50),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("batch_id", "video_id", name="UQ_BatchItems"),
    )
    op.create_index("ix_batchitems_batch", "BatchItems", ["batch_id"])
    op.create_index("ix_batchitems_video", "BatchItems", ["video_id"])

    # Jobs table
    op.create_table(
        "Jobs",
        sa.Column(
            "job_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "video_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Videos.video_id"),
            nullable=False,
        ),
        sa.Column(
            "batch_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Batches.batch_id"),
            nullable=True,
        ),
        sa.Column("job_type", NVARCHAR(50), nullable=False),
        sa.Column(
            "stage",
            NVARCHAR(50),
            nullable=False,
            server_default="queued",
        ),
        sa.Column(
            "status",
            NVARCHAR(50),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("progress", sa.Integer(), nullable=True),
        sa.Column("error_message", NVARCHAR(None), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("correlation_id", NVARCHAR(50), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
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
    op.create_index("ix_jobs_video", "Jobs", ["video_id"])
    op.create_index("ix_jobs_batch", "Jobs", ["batch_id"])
    op.create_index("ix_jobs_status", "Jobs", ["status"])
    op.create_index("ix_jobs_correlation", "Jobs", ["correlation_id"])
    op.create_index("ix_jobs_created", "Jobs", ["created_at"])


def downgrade() -> None:
    """Drop Batches, BatchItems, and Jobs tables."""
    op.drop_table("Jobs")
    op.drop_table("BatchItems")
    op.drop_table("Batches")
