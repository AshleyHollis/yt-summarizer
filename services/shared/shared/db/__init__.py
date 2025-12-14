"""Shared database module."""

from .connection import (
    DatabaseConnection,
    create_engine,
    create_session_factory,
    get_db,
    get_database_url,
    get_session,
)
from .job_service import (
    mark_job_completed,
    mark_job_failed,
    mark_job_running,
    update_job_status,
)
from .models import (
    Artifact,
    Base,
    Batch,
    BatchItem,
    Channel,
    Facet,
    Job,
    Relationship,
    Segment,
    TimestampMixin,
    Video,
    VideoFacet,
    generate_uuid,
)

__all__ = [
    "Artifact",
    "Base",
    "Batch",
    "BatchItem",
    "Channel",
    "DatabaseConnection",
    "Facet",
    "Job",
    "Relationship",
    "Segment",
    "TimestampMixin",
    "Video",
    "VideoFacet",
    "create_engine",
    "create_session_factory",
    "generate_uuid",
    "get_database_url",
    "get_db",
    "get_session",
    "mark_job_completed",
    "mark_job_failed",
    "mark_job_running",
    "update_job_status",
]
