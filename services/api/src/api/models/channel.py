"""Channel Pydantic models for API responses."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .base import BaseResponse, TimestampMixin
from .library import FacetTag


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
    top_facets: list[FacetTag] = Field(default_factory=list, description="Most common facets in this channel")
