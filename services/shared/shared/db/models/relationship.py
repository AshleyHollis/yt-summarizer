"""Relationship, Facet, and VideoFacet SQLAlchemy models."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from .channel import Video
    from .segment import Segment


class Relationship(Base, TimestampMixin):
    """Connections between videos with evidence and rationale."""

    __tablename__ = "Relationships"

    relationship_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    source_video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    target_video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    evidence_segment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("Segments.segment_id"),
        nullable=True,
    )
    evidence_text: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Traceability
    model_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Relationships
    source_video: Mapped["Video"] = relationship(
        "Video",
        foreign_keys=[source_video_id],
    )
    target_video: Mapped["Video"] = relationship(
        "Video",
        foreign_keys=[target_video_id],
    )
    evidence_segment: Mapped["Segment | None"] = relationship("Segment")

    __table_args__ = (
        Index("ix_relationships_source", "source_video_id"),
        Index("ix_relationships_target", "target_video_id"),
        Index("ix_relationships_type", "relationship_type"),
    )


class Facet(Base):
    """Generic metadata categories."""

    __tablename__ = "Facets"

    facet_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    facet_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    video_facets: Mapped[list["VideoFacet"]] = relationship(
        "VideoFacet",
        back_populates="facet",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_facets_type", "facet_type"),
        Index("ix_facets_name", "name"),
    )


class VideoFacet(Base):
    """Many-to-many relationship between videos and facets."""

    __tablename__ = "VideoFacets"

    video_facet_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    facet_id: Mapped[UUID] = mapped_column(
        ForeignKey("Facets.facet_id"),
        nullable=False,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_segment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("Segments.segment_id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    video: Mapped["Video"] = relationship("Video")
    facet: Mapped["Facet"] = relationship(
        "Facet",
        back_populates="video_facets",
    )
    evidence_segment: Mapped["Segment | None"] = relationship("Segment")

    __table_args__ = (
        Index("ix_videofacets_video", "video_id"),
        Index("ix_videofacets_facet", "facet_id"),
    )
