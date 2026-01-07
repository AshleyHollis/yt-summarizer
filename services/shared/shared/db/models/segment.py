"""Segment SQLAlchemy model with vector embeddings."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, generate_uuid

if TYPE_CHECKING:
    from .channel import Video


class Segment(Base):
    """Chunks of transcript with embeddings for semantic search."""

    __tablename__ = "Segments"

    segment_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    start_time: Mapped[float] = mapped_column(Float, nullable=False)  # seconds
    end_time: Mapped[float] = mapped_column(Float, nullable=False)  # seconds
    text: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Embedding stored as binary blob - VECTOR(1536) in SQL Server
    # Handled via raw SQL for vector operations
    # embedding column will be added in migration with VECTOR type
    # Traceability
    model_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    video: Mapped["Video"] = relationship(
        "Video",
        back_populates="segments",
    )

    __table_args__ = (
        Index("ix_segments_video", "video_id"),
        Index("ix_segments_times", "video_id", "start_time", "end_time"),
    )
