"""Channel service for channel ingestion operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.models import Channel, Video
    from shared.logging.config import get_logger
except ImportError:
    from typing import Any

    Channel = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)


from ..models.channel import (
    ChannelVideo,
    ChannelVideosResponse,
    FetchChannelRequest,
)
from .youtube_service import get_youtube_service

logger = get_logger(__name__)


class ChannelService:
    """Service for channel ingestion operations."""

    def __init__(self, session: AsyncSession):
        """Initialize the channel service.

        Args:
            session: Database session.
        """
        self.session = session
        self.youtube_service = get_youtube_service()

    async def fetch_channel_videos(
        self,
        request: FetchChannelRequest,
    ) -> ChannelVideosResponse:
        """Fetch videos from a YouTube channel for ingestion selection.

        Args:
            request: Fetch channel request with URL, cursor, limit.

        Returns:
            ChannelVideosResponse with videos and pagination info.
        """
        logger.info(
            "Fetching channel videos",
            channel_url=request.channel_url,
            cursor=request.cursor,
            limit=request.limit,
        )

        # Fetch from YouTube
        result = await self.youtube_service.fetch_channel_videos(
            channel_url=request.channel_url,
            limit=request.limit,
            cursor=request.cursor,
        )

        # Check if channel exists in DB
        channel_db = await self._get_channel_by_youtube_id(result["youtube_channel_id"])

        # Get already ingested video IDs
        ingested_video_ids = await self._get_ingested_video_ids(
            [v["youtube_video_id"] for v in result["videos"]]
        )

        # Build response with ingestion status
        videos = []
        for video_data in result["videos"]:
            videos.append(
                ChannelVideo(
                    youtube_video_id=video_data["youtube_video_id"],
                    title=video_data["title"],
                    duration=video_data["duration"],
                    publish_date=video_data["publish_date"],
                    thumbnail_url=video_data["thumbnail_url"],
                    already_ingested=video_data["youtube_video_id"] in ingested_video_ids,
                )
            )

        return ChannelVideosResponse(
            channel_id=channel_db.channel_id if channel_db else None,
            youtube_channel_id=result["youtube_channel_id"],
            channel_name=result["channel_name"],
            total_video_count=result.get("total_video_count"),
            returned_count=len(videos),
            videos=videos,
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
        )

    async def _get_channel_by_youtube_id(
        self,
        youtube_channel_id: str,
    ) -> Channel | None:
        """Get channel from DB by YouTube channel ID.

        Args:
            youtube_channel_id: YouTube channel ID.

        Returns:
            Channel model or None.
        """
        result = await self.session.execute(
            select(Channel).where(Channel.youtube_channel_id == youtube_channel_id)
        )
        return result.scalar_one_or_none()

    async def _get_ingested_video_ids(
        self,
        youtube_video_ids: list[str],
    ) -> set[str]:
        """Get set of YouTube video IDs that are already ingested.

        Args:
            youtube_video_ids: List of YouTube video IDs to check.

        Returns:
            Set of ingested YouTube video IDs.
        """
        if not youtube_video_ids:
            return set()

        result = await self.session.execute(
            select(Video.youtube_video_id).where(Video.youtube_video_id.in_(youtube_video_ids))
        )
        return {row[0] for row in result.fetchall()}

    async def get_or_create_channel(
        self,
        youtube_channel_id: str,
        channel_name: str,
    ) -> Channel:
        """Get or create a channel in the database.

        Args:
            youtube_channel_id: YouTube channel ID.
            channel_name: Channel name.

        Returns:
            Channel model (existing or newly created).
        """
        # Check if exists
        channel = await self._get_channel_by_youtube_id(youtube_channel_id)
        if channel:
            return channel

        # Create new channel
        channel = Channel(
            youtube_channel_id=youtube_channel_id,
            name=channel_name,
        )
        self.session.add(channel)
        await self.session.flush()

        logger.info(
            "Created channel",
            channel_id=str(channel.channel_id),
            youtube_channel_id=youtube_channel_id,
            name=channel_name,
        )

        return channel

    async def get_channel(self, channel_id: UUID) -> Channel | None:
        """Get channel by ID.

        Args:
            channel_id: Internal channel ID.

        Returns:
            Channel model or None.
        """
        result = await self.session.execute(select(Channel).where(Channel.channel_id == channel_id))
        return result.scalar_one_or_none()
