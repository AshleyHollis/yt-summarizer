"""Allow system jobs for backup status.

Revision ID: 017
Revises: 016
Create Date: 2026-06-09

"""

import sqlalchemy as sa
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER

from alembic import op

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "Jobs",
        "video_id",
        existing_type=UNIQUEIDENTIFIER(),
        nullable=True,
    )
    op.add_column(
        "Jobs",
        sa.Column(
            "metadata_json",
            sa.Text(),
            nullable=True,
            comment="Compact JSON metadata for system/admin jobs",
        ),
    )
    op.create_index(
        "ix_jobs_system_type_created",
        "Jobs",
        ["job_type", "video_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_jobs_system_type_created", table_name="Jobs")
    op.drop_column("Jobs", "metadata_json")
    op.alter_column(
        "Jobs",
        "video_id",
        existing_type=UNIQUEIDENTIFIER(),
        nullable=False,
    )
