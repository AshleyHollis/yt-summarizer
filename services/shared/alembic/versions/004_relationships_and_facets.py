"""Relationships, Facets, and VideoFacets tables.

Revision ID: 004
Revises: 003
Create Date: 2025-01-01 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.mssql import NVARCHAR, UNIQUEIDENTIFIER

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create Relationships, Facets, and VideoFacets tables."""
    # Relationships table
    op.create_table(
        "Relationships",
        sa.Column(
            "relationship_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column(
            "source_video_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Videos.video_id"),
            nullable=False,
        ),
        sa.Column(
            "target_video_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Videos.video_id"),
            nullable=False,
        ),
        sa.Column("relationship_type", NVARCHAR(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rationale", NVARCHAR(500), nullable=True),
        sa.Column("evidence_type", NVARCHAR(50), nullable=True),
        sa.Column(
            "evidence_segment_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Segments.segment_id"),
            nullable=True,
        ),
        sa.Column("evidence_text", NVARCHAR(500), nullable=True),
        sa.Column("model_name", NVARCHAR(100), nullable=True),
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
        sa.UniqueConstraint(
            "source_video_id",
            "target_video_id",
            "relationship_type",
            name="UQ_Relationships",
        ),
    )
    op.create_index("ix_relationships_source", "Relationships", ["source_video_id"])
    op.create_index("ix_relationships_target", "Relationships", ["target_video_id"])
    op.create_index("ix_relationships_type", "Relationships", ["relationship_type"])

    # Facets table
    op.create_table(
        "Facets",
        sa.Column(
            "facet_id",
            UNIQUEIDENTIFIER(),
            primary_key=True,
            server_default=sa.text("NEWSEQUENTIALID()"),
        ),
        sa.Column("name", NVARCHAR(200), nullable=False),
        sa.Column("facet_type", NVARCHAR(50), nullable=False),
        sa.Column("description", NVARCHAR(500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("name", "facet_type", name="UQ_Facets"),
    )
    op.create_index("ix_facets_type", "Facets", ["facet_type"])
    op.create_index("ix_facets_name", "Facets", ["name"])

    # VideoFacets table
    op.create_table(
        "VideoFacets",
        sa.Column(
            "video_facet_id",
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
            "facet_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Facets.facet_id"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "evidence_segment_id",
            UNIQUEIDENTIFIER(),
            sa.ForeignKey("Segments.segment_id"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("video_id", "facet_id", name="UQ_VideoFacets"),
    )
    op.create_index("ix_videofacets_video", "VideoFacets", ["video_id"])
    op.create_index("ix_videofacets_facet", "VideoFacets", ["facet_id"])


def downgrade() -> None:
    """Drop Relationships, Facets, and VideoFacets tables."""
    op.drop_table("VideoFacets")
    op.drop_table("Facets")
    op.drop_table("Relationships")
