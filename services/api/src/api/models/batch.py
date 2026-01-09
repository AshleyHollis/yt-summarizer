"""Batch Pydantic models for API requests and responses."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from .base import BaseResponse


class BatchStatus(StrEnum):
    """Status of a batch job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BatchItemStatus(StrEnum):
    """Status of an individual batch item."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


# =============================================================================
# Request Models
# =============================================================================


class CreateBatchRequest(BaseResponse):
    """Request to create a batch for video ingestion."""

    channel_id: UUID | None = Field(
        default=None,
        description="Channel ID if ingesting from a known channel",
    )
    youtube_channel_id: str | None = Field(
        default=None,
        description="YouTube channel ID for tracking",
    )
    name: str = Field(
        description="Display name for this batch",
        examples=["Wildman Movement Playlist"],
    )
    video_ids: list[str] = Field(
        default_factory=list,
        description="List of YouTube video IDs to ingest",
    )
    ingest_all: bool = Field(
        default=False,
        description="If true, ingest all videos from the channel (ignores videoIds)",
    )


# =============================================================================
# Response Models
# =============================================================================


class BatchItem(BaseResponse):
    """An individual video item within a batch."""

    id: UUID = Field(description="Batch item ID")
    video_id: UUID | None = Field(default=None, description="Video ID once created")
    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    status: BatchItemStatus = Field(description="Item processing status")
    error_message: str | None = Field(default=None, description="Error message if failed")
    created_at: datetime = Field(description="When item was added")
    updated_at: datetime = Field(description="Last status update")


class BatchResponse(BaseResponse):
    """Summary of a batch for list views."""

    id: UUID = Field(description="Batch ID")
    name: str = Field(description="Batch display name")
    channel_name: str | None = Field(default=None, description="Associated channel name")
    status: BatchStatus = Field(description="Overall batch status")
    total_count: int = Field(description="Total videos in batch")
    pending_count: int = Field(description="Videos pending processing")
    running_count: int = Field(description="Videos currently processing")
    succeeded_count: int = Field(description="Videos successfully processed")
    failed_count: int = Field(description="Videos that failed processing")
    created_at: datetime = Field(description="Batch creation time")
    updated_at: datetime = Field(description="Last batch update")


class BatchDetailResponse(BatchResponse):
    """Detailed batch response including items."""

    items: list[BatchItem] = Field(default_factory=list, description="All items in the batch")


class BatchListResponse(BaseResponse):
    """Paginated list of batches."""

    batches: list[BatchResponse] = Field(default_factory=list)
    total_count: int = Field(description="Total batches available")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=20, description="Items per page")


class BatchRetryResponse(BaseResponse):
    """Response from retrying failed items in a batch."""

    batch_id: UUID = Field(description="Batch ID")
    retried_count: int = Field(description="Number of items queued for retry")
    message: str = Field(description="Status message")
