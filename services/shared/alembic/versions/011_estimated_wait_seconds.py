"""Add estimated_wait_seconds to Jobs and JobHistory.

Revision ID: 011
Revises: 010
Create Date: 2026-01-05

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add estimated_wait_seconds column to Jobs and JobHistory."""
    op.add_column(
        "Jobs",
        sa.Column(
            "estimated_wait_seconds",
            sa.Float(),
            nullable=True,
            comment="Predicted queue wait time at job creation",
        ),
    )
    op.add_column(
        "JobHistory",
        sa.Column(
            "estimated_wait_seconds",
            sa.Float(),
            nullable=True,
            comment="Predicted queue wait time at submission (for accuracy tracking)",
        ),
    )


def downgrade() -> None:
    """Remove estimated_wait_seconds columns."""
    op.drop_column("JobHistory", "estimated_wait_seconds")
    op.drop_column("Jobs", "estimated_wait_seconds")
