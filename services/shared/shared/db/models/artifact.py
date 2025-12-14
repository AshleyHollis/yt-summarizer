"""Artifact SQLAlchemy model."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, generate_uuid

if TYPE_CHECKING:
    from .channel import Video


class Artifact(Base):
    """Derived outputs (transcripts, summaries) stored in blob with references."""

    __tablename__ = "Artifacts"

    artifact_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blob_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    content_length: Mapped[int] = mapped_column(Integer, nullable=False)
    # Traceability metadata
    model_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    parameters: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    video: Mapped["Video"] = relationship(
        "Video",
        back_populates="artifacts",
    )

    __table_args__ = (
        Index("ix_artifacts_video", "video_id"),
        Index("ix_artifacts_type", "artifact_type"),
    )
