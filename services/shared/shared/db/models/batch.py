"""Batch and Job SQLAlchemy models."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from .channel import Channel, Video


class Batch(Base):
    """Groups videos queued together for processing."""

    __tablename__ = "Batches"

    batch_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    channel_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("Channels.channel_id"),
        nullable=True,
    )
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    total_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pending_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    running_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    succeeded_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    channel: Mapped["Channel | None"] = relationship(
        "Channel",
        back_populates="batches",
    )
    items: Mapped[list["BatchItem"]] = relationship(
        "BatchItem",
        back_populates="batch",
        lazy="selectin",
    )
    jobs: Mapped[list["Job"]] = relationship(
        "Job",
        back_populates="batch",
        lazy="selectin",
    )


class BatchItem(Base):
    """Links videos to batches."""

    __tablename__ = "BatchItems"

    batch_item_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    batch_id: Mapped[UUID] = mapped_column(
        ForeignKey("Batches.batch_id"),
        nullable=False,
    )
    video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    batch: Mapped["Batch"] = relationship(
        "Batch",
        back_populates="items",
    )
    video: Mapped["Video"] = relationship("Video")

    __table_args__ = (
        Index("ix_batchitems_batch", "batch_id"),
        Index("ix_batchitems_video", "video_id"),
    )


class Job(Base, TimestampMixin):
    """Processing tasks for videos."""

    __tablename__ = "Jobs"

    job_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    video_id: Mapped[UUID] = mapped_column(
        ForeignKey("Videos.video_id"),
        nullable=False,
    )
    batch_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("Batches.batch_id"),
        nullable=True,
    )
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    stage: Mapped[str] = mapped_column(
        String(50),
        default="queued",
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    video: Mapped["Video"] = relationship(
        "Video",
        back_populates="jobs",
    )
    batch: Mapped["Batch | None"] = relationship(
        "Batch",
        back_populates="jobs",
    )

    __table_args__ = (
        Index("ix_jobs_video", "video_id"),
        Index("ix_jobs_batch", "batch_id"),
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_correlation", "correlation_id"),
        Index("ix_jobs_created", "created_at"),
    )
