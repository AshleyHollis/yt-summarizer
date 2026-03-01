"""Usage record model for tracking per-user quota consumption."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, generate_uuid


class UsageRecord(Base):
    """Tracks individual operations for quota enforcement."""

    __tablename__ = "UsageRecords"

    usage_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("Users.user_id"),
        nullable=False,
    )
    operation_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Operation type: 'video_submit' or 'copilot_query'",
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Optional reference to the resource (video_id, thread_id, etc.)",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=func.sysutcdatetime(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_usage_user_op_created", "user_id", "operation_type", "created_at"),
        Index("ix_usage_created", "created_at"),
    )
