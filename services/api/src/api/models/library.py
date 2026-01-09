"""Library Pydantic models for browsing and filtering videos."""

from datetime import date, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from .base import BaseResponse, TimestampMixin


class ProcessingStatusFilter(str, Enum):
    """Video processing status for filtering."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class SortField(str, Enum):
    """Available sort fields for video list."""

    PUBLISH_DATE = "publishDate"
    TITLE = "title"
    CREATED_AT = "createdAt"


class SortOrder(str, Enum):
    """Sort order direction."""

    ASC = "asc"
    DESC = "desc"


class FacetTag(BaseResponse):
    """Facet/tag attached to a video."""

    facet_id: UUID = Field(description="Facet ID")
    name: str = Field(description="Facet name")
    type: str = Field(description="Facet type (topic, format, level, etc.)")


class VideoCard(BaseResponse):
    """Video summary for list display."""

    video_id: UUID = Field(description="Internal video ID")
    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    channel_id: UUID = Field(description="Channel ID")
    channel_name: str = Field(description="Channel name")
    channel_thumbnail_url: str | None = Field(default=None, description="Channel avatar URL")
    duration: int = Field(description="Duration in seconds")
    publish_date: datetime = Field(description="Video publish date")
    thumbnail_url: str | None = Field(default=None, description="Video thumbnail URL")
    processing_status: str = Field(description="Current processing status")
    segment_count: int = Field(default=0, description="Number of transcript segments")
    facets: list[FacetTag] = Field(default_factory=list, description="Video facets/tags")

    @property
    def youtube_url(self) -> str:
        """Get the YouTube URL for this video."""
        return f"https://www.youtube.com/watch?v={self.youtube_video_id}"


class ChannelSummaryLibrary(BaseResponse):
    """Channel summary in video detail context."""

    channel_id: UUID = Field(description="Channel ID")
    youtube_channel_id: str = Field(description="YouTube channel ID")
    name: str = Field(description="Channel name")
    thumbnail_url: str | None = Field(default=None, description="Channel thumbnail URL")


class ArtifactInfo(BaseResponse):
    """Information about a video artifact (transcript, summary)."""

    artifact_id: UUID = Field(description="Artifact ID")
    type: str = Field(description="Artifact type (transcript, summary)")
    content_length: int = Field(description="Content length in characters")
    model_name: str | None = Field(default=None, description="AI model used")
    created_at: datetime = Field(description="When artifact was created")


class VideoDetailResponse(BaseResponse, TimestampMixin):
    """Full video details for detail page."""

    video_id: UUID = Field(description="Internal video ID")
    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    description: str | None = Field(default=None, description="Video description")
    channel: ChannelSummaryLibrary = Field(description="Channel information")
    duration: int = Field(description="Duration in seconds")
    publish_date: datetime = Field(description="Video publish date")
    thumbnail_url: str | None = Field(default=None, description="Video thumbnail URL")
    youtube_url: str = Field(description="YouTube video URL")
    processing_status: str = Field(description="Current processing status")
    summary: str | None = Field(default=None, description="AI-generated summary")
    summary_artifact: ArtifactInfo | None = Field(default=None, description="Summary artifact info")
    transcript_artifact: ArtifactInfo | None = Field(default=None, description="Transcript artifact info")
    segment_count: int = Field(default=0, description="Number of transcript segments")
    relationship_count: int = Field(default=0, description="Number of related videos")
    facets: list[FacetTag] = Field(default_factory=list, description="Video facets/tags")


class VideoListResponse(BaseResponse):
    """Paginated list of videos for library browsing."""

    videos: list[VideoCard] = Field(description="List of video cards")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_count: int = Field(description="Total number of videos matching filters")

    @property
    def total_pages(self) -> int:
        """Calculate total pages."""
        return (self.total_count + self.page_size - 1) // self.page_size if self.page_size > 0 else 0

    @property
    def has_next(self) -> bool:
        """Check if there's a next page."""
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        """Check if there's a previous page."""
        return self.page > 1


class Segment(BaseResponse):
    """Transcript segment with timestamp."""

    segment_id: UUID = Field(description="Segment ID")
    sequence_number: int = Field(description="Order in transcript")
    start_time: float = Field(description="Start time in seconds")
    end_time: float = Field(description="End time in seconds")
    text: str = Field(description="Segment text")
    youtube_url: str = Field(description="YouTube URL with timestamp")


class SegmentListResponse(BaseResponse):
    """Paginated list of segments for a video."""

    video_id: UUID = Field(description="Video ID")
    segments: list[Segment] = Field(description="List of segments")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_count: int = Field(description="Total number of segments")


class VideoFilterParams(BaseModel):
    """Query parameters for filtering videos."""

    channel_id: UUID | None = Field(default=None, description="Filter by channel")
    from_date: date | None = Field(default=None, description="Filter by publish date (from)")
    to_date: date | None = Field(default=None, description="Filter by publish date (to)")
    facets: list[UUID] | None = Field(default=None, description="Filter by facet IDs")
    status: ProcessingStatusFilter | None = Field(default=None, description="Filter by processing status")
    search: str | None = Field(default=None, description="Text search in title/description")
    sort_by: SortField = Field(default=SortField.PUBLISH_DATE, description="Sort field")
    sort_order: SortOrder = Field(default=SortOrder.DESC, description="Sort order")
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=10, ge=1, le=50, description="Items per page")


class LibraryStatsResponse(BaseResponse):
    """Overall library statistics."""

    total_channels: int = Field(description="Total number of channels")
    total_videos: int = Field(description="Total number of videos")
    completed_videos: int = Field(description="Number of completed videos")
    total_segments: int = Field(description="Total transcript segments")
    total_relationships: int = Field(description="Total video relationships")
    total_facets: int = Field(description="Total unique facets")
    last_updated_at: datetime | None = Field(default=None, description="Last video update time")
