"""SQLAlchemy model for logging proxied yt-dlp requests."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ProxyRequestLog(Base):
    """Persistent record of a single proxied yt-dlp request.

    Written by ProxyService.log_request() after each proxied call. Used for
    bandwidth tracking (FR-003), rate-limit audit, and debugging.

    Columns:
        id              - Primary key (UUID).
        job_id          - FK to the Job that triggered this call (nullable for
                          API-originated calls without a job context).
        service         - Originating service name (e.g. 'transcribe-worker', 'api').
        operation       - High-level operation label (e.g. 'fetch_transcript').
        proxy_url_masked- Proxy URL with password replaced by '***'.
        success         - True if the yt-dlp call completed without exception.
        duration_ms     - Wall-clock time for the call in milliseconds.
        error_type      - Exception class name on failure (nullable).
        bytes_used      - Approximate bytes consumed (0 when unknown).
        created_at      - UTC timestamp when the record was inserted.
    """

    __tablename__ = "proxy_request_logs"

    id: Mapped[UUID] = mapped_column(
        UNIQUEIDENTIFIER,
        primary_key=True,
        default=lambda: __import__("uuid").uuid4(),
        server_default="NEWID()",
    )
    job_id: Mapped[UUID | None] = mapped_column(
        UNIQUEIDENTIFIER,
        ForeignKey("jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    operation: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    proxy_url_masked: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bytes_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=func.sysutcdatetime(),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )
