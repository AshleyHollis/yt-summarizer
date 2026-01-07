"""Channel and Video SQLAlchemy models."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from .artifact import Artifact
    from .batch import Batch
    from .job import Job
    from .segment import Segment


class Channel(Base, TimestampMixin):
    """Represents a YouTube channel."""

    __tablename__ = "Channels"

    channel_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    youtube_channel_id: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    thumbnail_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    video_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    videos: Mapped[list["Video"]] = relationship(
        "Video",
        back_populates="channel",
        lazy="selectin",
    )
    batches: Mapped[list["Batch"]] = relationship(
        "Batch",
        back_populates="channel",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_channels_youtube_id", "youtube_channel_id"),
    )


class Video(Base, TimestampMixin):
    """Represents a YouTube video."""

    __tablename__ = "Videos"

    video_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    youtube_video_id: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        nullable=False,
    )
    channel_id: Mapped[UUID] = mapped_column(
        ForeignKey("Channels.channel_id"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration: Mapped[int] = mapped_column(Integer, nullable=False)  # seconds
    publish_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    thumbnail_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    processing_status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    channel: Mapped["Channel"] = relationship(
        "Channel",
        back_populates="videos",
    )
    artifacts: Mapped[list["Artifact"]] = relationship(
        "Artifact",
        back_populates="video",
        lazy="selectin",
    )
    segments: Mapped[list["Segment"]] = relationship(
        "Segment",
        back_populates="video",
        lazy="selectin",
    )
    jobs: Mapped[list["Job"]] = relationship(
        "Job",
        back_populates="video",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_videos_youtube_id", "youtube_video_id"),
        Index("ix_videos_channel", "channel_id"),
        Index("ix_videos_publish_date", "publish_date"),
        Index("ix_videos_status", "processing_status"),
    )
