"""Add processing mode to batches and jobs.

Revision ID: 016
Revises: 015
Create Date: 2026-06-08

"""

import sqlalchemy as sa

from alembic import op

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "Batches",
        sa.Column(
            "processing_mode",
            sa.String(50),
            nullable=False,
            server_default="full_analysis",
            comment="'transcript_only' or 'full_analysis'",
        ),
    )
    op.add_column(
        "Jobs",
        sa.Column(
            "processing_mode",
            sa.String(50),
            nullable=False,
            server_default="full_analysis",
            comment="'transcript_only' or 'full_analysis'",
        ),
    )
    op.alter_column("Batches", "processing_mode", server_default=None)
    op.alter_column("Jobs", "processing_mode", server_default=None)


def downgrade() -> None:
    op.drop_column("Jobs", "processing_mode")
    op.drop_column("Batches", "processing_mode")
