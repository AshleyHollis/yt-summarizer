"""Expedite request model for quota bypass approval workflow."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, generate_uuid


class ExpediteRequest(Base):
    """User request to expedite processing of queued videos."""

    __tablename__ = "ExpediteRequests"

    request_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("Users.user_id"),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional reason provided by user for expedite request",
    )
    video_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Number of queued videos at time of request",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
        comment="Request status: 'pending', 'approved', or 'denied'",
    )
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("Users.user_id"),
        nullable=True,
        comment="Admin user who reviewed the request",
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=func.sysutcdatetime(),
        nullable=False,
    )

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])

    __table_args__ = (
        Index("ix_expedite_user", "user_id"),
        Index("ix_expedite_status", "status"),
        Index("ix_expedite_created", "created_at"),
    )
