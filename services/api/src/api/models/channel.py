"""Channel Pydantic models for API responses."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .base import BaseResponse, TimestampMixin
from .library import FacetTag

# =============================================================================
# Channel Ingestion Models (US2)
# =============================================================================


class FetchChannelRequest(BaseResponse):
    """Request to fetch videos from a YouTube channel."""

    channel_url: str = Field(
        description="YouTube channel URL or ID",
        examples=["https://www.youtube.com/@MarkWildman"],
    )
    cursor: str | None = Field(
        default=None,
        description="Pagination cursor for loading more videos (returned from previous response)",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=100,
        description="Maximum videos to return (default 100, max 100)",
    )


class ChannelVideo(BaseResponse):
    """Video from a channel available for ingestion."""

    youtube_video_id: str = Field(description="YouTube video ID")
    title: str = Field(description="Video title")
    duration: int = Field(description="Duration in seconds")
    publish_date: datetime = Field(description="Video publish date")
    thumbnail_url: str | None = Field(default=None, description="Video thumbnail URL")
    already_ingested: bool = Field(
        default=False, description="Whether video is already in the library"
    )


class ChannelVideosResponse(BaseResponse):
    """Response containing videos from a YouTube channel."""

    channel_id: UUID | None = Field(
        default=None, description="Internal channel ID (if exists in DB)"
    )
    youtube_channel_id: str = Field(description="YouTube channel ID")
    channel_name: str = Field(description="Channel name")
    total_video_count: int | None = Field(
        default=None, description="Total videos in channel (if known)"
    )
    returned_count: int = Field(description="Number of videos in this response")
    videos: list[ChannelVideo] = Field(
        default_factory=list, description="Videos available for ingestion"
    )
    next_cursor: str | None = Field(
        default=None, description="Cursor for next page (null if no more videos)"
    )
    has_more: bool = Field(default=False, description="Whether more videos are available")


# =============================================================================
# Library Channel Models (US3)
# =============================================================================


class ChannelCard(BaseResponse):
    """Channel summary for list display."""

    channel_id: UUID = Field(description="Internal channel ID")
    youtube_channel_id: str = Field(description="YouTube channel ID")
    name: str = Field(description="Channel name")
    thumbnail_url: str | None = Field(default=None, description="Channel thumbnail URL")
    video_count: int = Field(description="Number of videos from this channel")
    last_synced_at: datetime | None = Field(default=None, description="Last sync time")

    @property
    def youtube_url(self) -> str:
        """Get the YouTube channel URL."""
        return f"https://www.youtube.com/channel/{self.youtube_channel_id}"


class ChannelListResponse(BaseResponse):
    """Paginated list of channels."""

    channels: list[ChannelCard] = Field(description="List of channel cards")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_count: int = Field(description="Total number of channels")


class ChannelDetailResponse(BaseResponse, TimestampMixin):
    """Full channel details."""

    channel_id: UUID = Field(description="Internal channel ID")
    youtube_channel_id: str = Field(description="YouTube channel ID")
    name: str = Field(description="Channel name")
    description: str | None = Field(default=None, description="Channel description")
    thumbnail_url: str | None = Field(default=None, description="Channel thumbnail URL")
    youtube_url: str = Field(description="YouTube channel URL")
    video_count: int = Field(description="Total videos from this channel")
    completed_video_count: int = Field(description="Number of completed videos")
    last_synced_at: datetime | None = Field(default=None, description="Last sync time")
    top_facets: list[FacetTag] = Field(
        default_factory=list, description="Most common facets in this channel"
    )
