"""Create JobHistory table for tracking completed job processing times.

This table stores historical job completion data to enable:
- ETA calculations based on rolling averages
- Queue position visibility
- Processing time analytics correlated with video duration

Revision ID: 009
Revises: 008
Create Date: 2026-01-05

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER, NVARCHAR


# revision identifiers, used by Alembic.
revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create JobHistory table."""
    op.create_table(
        "JobHistory",
        sa.Column(
            "history_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "job_id",
            UNIQUEIDENTIFIER(),
            nullable=False,
        ),
        sa.Column(
            "video_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Videos.video_id"),
            nullable=False,
        ),
        sa.Column(
            "job_type",
            NVARCHAR(50),
            nullable=False,
        ),
        sa.Column(
            "video_duration_seconds",
            sa.Integer(),
            nullable=True,
            comment="Duration of the video in seconds for correlation analysis",
        ),
        sa.Column(
            "processing_duration_seconds",
            sa.Float(),
            nullable=False,
            comment="Time taken to process this job in seconds",
        ),
        sa.Column(
            "started_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "success",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
            comment="Whether the job completed successfully",
        ),
        sa.Column(
            "retry_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
    )
    
    # Indexes for efficient querying
    op.create_index(
        "ix_jobhistory_job_type",
        "JobHistory",
        ["job_type"],
    )
    op.create_index(
        "ix_jobhistory_video",
        "JobHistory",
        ["video_id"],
    )
    op.create_index(
        "ix_jobhistory_completed",
        "JobHistory",
        ["completed_at"],
    )
    # Composite index for ETA calculations (recent successful jobs by type)
    op.create_index(
        "ix_jobhistory_eta_calc",
        "JobHistory",
        ["job_type", "success", "completed_at"],
    )


def downgrade() -> None:
    """Drop JobHistory table."""
    op.drop_index("ix_jobhistory_eta_calc", table_name="JobHistory")
    op.drop_index("ix_jobhistory_completed", table_name="JobHistory")
    op.drop_index("ix_jobhistory_video", table_name="JobHistory")
    op.drop_index("ix_jobhistory_job_type", table_name="JobHistory")
    op.drop_table("JobHistory")
