"""Add wait time and enforced delay tracking to JobHistory.

Revision ID: 010
Revises: 009
Create Date: 2026-01-05

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add queued_at, wait_seconds, and enforced_delay_seconds columns to JobHistory."""
    op.add_column(
        "JobHistory",
        sa.Column("queued_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "JobHistory",
        sa.Column(
            "wait_seconds",
            sa.Float(),
            nullable=True,
            comment="Time in queue before processing started (started_at - queued_at)",
        ),
    )
    op.add_column(
        "JobHistory",
        sa.Column(
            "enforced_delay_seconds",
            sa.Float(),
            nullable=True,
            comment="Intentional delay (e.g., yt-dlp subtitle_sleep for rate limiting)",
        ),
    )


def downgrade() -> None:
    """Remove wait time and enforced delay columns from JobHistory."""
    op.drop_column("JobHistory", "enforced_delay_seconds")
    op.drop_column("JobHistory", "wait_seconds")
    op.drop_column("JobHistory", "queued_at")
