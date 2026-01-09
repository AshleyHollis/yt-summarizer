"""Artifacts and Segments tables with VECTOR column.

Revision ID: 003
Revises: 002
Create Date: 2025-01-01 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.mssql import NVARCHAR, UNIQUEIDENTIFIER

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create Artifacts and Segments tables."""
    # Artifacts table
    op.create_table(
        "Artifacts",
        sa.Column(
            "artifact_id",
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
        sa.Column("artifact_type", NVARCHAR(50), nullable=False),
        sa.Column("content_hash", NVARCHAR(64), nullable=True),
        sa.Column("blob_uri", NVARCHAR(500), nullable=False),
        sa.Column("content_length", sa.Integer(), nullable=False),
        sa.Column("model_name", NVARCHAR(100), nullable=True),
        sa.Column("model_version", NVARCHAR(50), nullable=True),
        sa.Column("parameters", NVARCHAR(None), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("video_id", "artifact_type", name="UQ_Artifacts"),
    )
    op.create_index("ix_artifacts_video", "Artifacts", ["video_id"])
    op.create_index("ix_artifacts_type", "Artifacts", ["artifact_type"])

    # Segments table (without VECTOR column initially - added via raw SQL)
    op.create_table(
        "Segments",
        sa.Column(
            "segment_id",
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
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("start_time", sa.Float(), nullable=False),
        sa.Column("end_time", sa.Float(), nullable=False),
        sa.Column("text", NVARCHAR(None), nullable=False),
        sa.Column("content_hash", NVARCHAR(64), nullable=False),
        sa.Column("model_name", NVARCHAR(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("video_id", "sequence_number", name="UQ_Segments"),
    )
    op.create_index("ix_segments_video", "Segments", ["video_id"])
    op.create_index(
        "ix_segments_times",
        "Segments",
        ["video_id", "start_time", "end_time"],
    )

    # Add embedding column - SQL Server 2025 supports native VECTOR type
    op.execute(
        """
        ALTER TABLE Segments
        ADD Embedding VECTOR(1536) NULL
        """
    )


def downgrade() -> None:
    """Drop Artifacts and Segments tables."""
    op.drop_table("Segments")
    op.drop_table("Artifacts")
