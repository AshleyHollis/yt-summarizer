"""Video Pydantic models for API requests and responses."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from .base import BaseResponse, PaginatedResponse, TimestampMixin


class ProcessingStatus(StrEnum):
    """Video processing status."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"  # YouTube is rate limiting, will retry automatically


class SubmitVideoRequest(BaseModel):
    """Request to submit a video for processing."""

    url: str = Field(
        description="YouTube video URL",
        examples=["https://www.youtube.com/watch?v=dQw4w9WgXcQ"],
    )

    @field_validator("url")
    @classmethod
    def validate_youtube_url(cls, v: str) -> str:
        """Validate that the URL is a valid YouTube video URL."""
        import re

        # YouTube URL patterns
        patterns = [
            r"^https?://(?:www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})",
            r"^https?://youtu\.be/([a-zA-Z0-9_-]{11})",
            r"^https?://(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]{11})",
            r"^https?://(?:www\.)?youtube\.com/v/([a-zA-Z0-9_-]{11})",
        ]

        for pattern in patterns:
            if re.match(pattern, v):
                return v

        raise ValueError("Invalid YouTube URL. Please provide a valid YouTube video URL.")


class ChannelSummary(BaseResponse):
    """Summary of a channel (embedded in video responses)."""

    channel_id: UUID = Field(description="Internal channel ID")
    youtube_channel_id: str = Field(description="YouTube channel ID")
    name: str = Field(description="Channel name")
    thumbnail_url: str | None = Field(default=None, description="Channel thumbnail URL")


class VideoResponse(BaseResponse, TimestampMixin):
    """Video response model."""

    video_id: UUID = Field(description="Internal video ID")
    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    description: str | None = Field(default=None, description="Video description")
    duration: int = Field(description="Video duration in seconds")
    publish_date: datetime = Field(description="Video publish date")
    thumbnail_url: str | None = Field(default=None, description="Video thumbnail URL")
    processing_status: ProcessingStatus = Field(description="Current processing status")
    error_message: str | None = Field(default=None, description="Error message if failed")
    channel: ChannelSummary | None = Field(default=None, description="Channel information")
    transcript_url: str | None = Field(default=None, description="URL to fetch transcript")
    summary_url: str | None = Field(default=None, description="URL to fetch summary")

    @property
    def youtube_url(self) -> str:
        """Get the YouTube URL for this video."""
        return f"https://www.youtube.com/watch?v={self.youtube_video_id}"


class VideoSummaryResponse(BaseResponse):
    """Minimal video response for lists."""

    video_id: UUID = Field(description="Internal video ID")
    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    duration: int = Field(description="Video duration in seconds")
    publish_date: datetime = Field(description="Video publish date")
    thumbnail_url: str | None = Field(default=None, description="Video thumbnail URL")
    processing_status: ProcessingStatus = Field(description="Current processing status")
    channel_name: str | None = Field(default=None, description="Channel name")


class SubmitVideoResponse(BaseResponse):
    """Response after submitting a video for processing."""

    video_id: UUID = Field(description="Internal video ID")
    youtube_video_id: str = Field(description="YouTube video ID")
    job_id: UUID = Field(description="Initial job ID for tracking")
    status: ProcessingStatus = Field(description="Initial processing status")
    message: str = Field(description="Status message")


class ReprocessVideoRequest(BaseModel):
    """Request to reprocess a video."""

    stages: list[str] | None = Field(
        default=None,
        description="Specific stages to reprocess (transcribe, summarize, embed, relationships). If null, reprocess all.",
    )


class VideoListResponse(PaginatedResponse[VideoSummaryResponse]):
    """Paginated list of videos."""

    pass


# Utility functions for URL parsing
def extract_youtube_video_id(url: str) -> str | None:
    """Extract YouTube video ID from a URL.

    Args:
        url: YouTube video URL.

    Returns:
        Video ID or None if not found.
    """
    import re

    patterns = [
        r"(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/v/)([a-zA-Z0-9_-]{11})",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    return None
