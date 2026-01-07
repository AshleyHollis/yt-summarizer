"""YouTube service for fetching channel and video data using yt-dlp."""

import asyncio
from datetime import datetime
from typing import Any

try:
    from shared.logging.config import get_logger
except ImportError:

    def get_logger(name):
        import logging

        return logging.getLogger(name)


logger = get_logger(__name__)


class YouTubeService:
    """Service for fetching YouTube data using yt-dlp."""

    @staticmethod
    def parse_channel_url(url: str) -> dict[str, str | None]:
        """Parse a YouTube channel URL to extract the identifier.

        Supports formats:
        - https://www.youtube.com/@MarkWildman
        - https://www.youtube.com/channel/UC1234567890
        - https://www.youtube.com/c/ChannelName
        - https://www.youtube.com/user/Username

        Args:
            url: YouTube channel URL.

        Returns:
            Dict with 'type' (handle, channel_id, custom, user) and 'value'.
        """
        import re

        url = url.strip()

        # Handle format: @ChannelHandle
        if match := re.match(r"https?://(?:www\.)?youtube\.com/@([\w.-]+)", url):
            return {"type": "handle", "value": match.group(1)}

        # Channel ID format: /channel/UC...
        if match := re.match(
            r"https?://(?:www\.)?youtube\.com/channel/(UC[\w-]+)", url
        ):
            return {"type": "channel_id", "value": match.group(1)}

        # Custom URL format: /c/ChannelName
        if match := re.match(r"https?://(?:www\.)?youtube\.com/c/([\w.-]+)", url):
            return {"type": "custom", "value": match.group(1)}

        # User format: /user/Username
        if match := re.match(r"https?://(?:www\.)?youtube\.com/user/([\w.-]+)", url):
            return {"type": "user", "value": match.group(1)}

        # Just a channel ID directly
        if url.startswith("UC") and len(url) == 24:
            return {"type": "channel_id", "value": url}

        # Handle as-is (might be @handle without URL)
        if url.startswith("@"):
            return {"type": "handle", "value": url[1:]}

        return {"type": "unknown", "value": url}

    @staticmethod
    def normalize_channel_url(url: str) -> str:
        """Normalize channel URL for yt-dlp extraction.

        Args:
            url: YouTube channel URL or identifier.

        Returns:
            Normalized URL suitable for yt-dlp.
        """
        parsed = YouTubeService.parse_channel_url(url)

        if parsed["type"] == "handle":
            return f"https://www.youtube.com/@{parsed['value']}/videos"
        elif parsed["type"] == "channel_id":
            return f"https://www.youtube.com/channel/{parsed['value']}/videos"
        elif parsed["type"] == "custom":
            return f"https://www.youtube.com/c/{parsed['value']}/videos"
        elif parsed["type"] == "user":
            return f"https://www.youtube.com/user/{parsed['value']}/videos"
        else:
            # Try as-is
            if not url.endswith("/videos"):
                return f"{url.rstrip('/')}/videos"
            return url

    async def fetch_channel_videos(
        self,
        channel_url: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Fetch videos from a YouTube channel.

        Uses yt-dlp's playlist extraction with playlistend for pagination.
        The cursor represents the starting index for the next page.

        Args:
            channel_url: YouTube channel URL.
            limit: Maximum videos to return.
            cursor: Starting index (as string) for pagination.

        Returns:
            Dict with channel info and video list.
        """
        import yt_dlp

        normalized_url = self.normalize_channel_url(channel_url)
        logger.info(
            "Fetching channel videos",
            original_url=channel_url,
            normalized_url=normalized_url,
            limit=limit,
            cursor=cursor,
        )

        # Parse cursor as starting index
        start_index = 1
        if cursor:
            try:
                start_index = int(cursor)
            except ValueError:
                logger.warning("Invalid cursor value, starting from 1", cursor=cursor)
                start_index = 1

        end_index = start_index + limit - 1

        ydl_opts = {
            "skip_download": True,
            "quiet": True,
            "no_warnings": True,
            "extract_flat": True,  # Only extract metadata, don't resolve each video
            "playliststart": start_index,
            "playlistend": end_index,
            "ignoreerrors": True,
        }

        try:
            loop = asyncio.get_event_loop()
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = await loop.run_in_executor(
                    None, lambda: ydl.extract_info(normalized_url, download=False)
                )

            if not info:
                raise ValueError("Failed to extract channel information")

            # Parse channel info
            channel_id = (
                info.get("channel_id")
                or info.get("uploader_id")
                or info.get("id", "unknown")
            )
            channel_name = (
                info.get("channel")
                or info.get("uploader")
                or info.get("title", "Unknown Channel")
            )

            # Get videos from entries
            entries = info.get("entries", []) or []
            videos = []

            for entry in entries:
                if not entry:
                    continue

                video_id = entry.get("id")
                if not video_id:
                    continue

                # Parse duration (may be None for live streams)
                duration = entry.get("duration") or 0

                # Parse publish date
                upload_date_str = entry.get("upload_date")
                if upload_date_str:
                    try:
                        publish_date = datetime.strptime(upload_date_str, "%Y%m%d")
                    except ValueError:
                        publish_date = datetime.utcnow()
                else:
                    publish_date = datetime.utcnow()

                # Get thumbnail
                thumbnail_url = entry.get("thumbnail")
                if not thumbnail_url:
                    thumbnail_url = f"https://img.youtube.com/vi/{video_id}/mqdefault.jpg"

                videos.append(
                    {
                        "youtube_video_id": video_id,
                        "title": entry.get("title") or f"Video {video_id}",
                        "duration": duration,
                        "publish_date": publish_date,
                        "thumbnail_url": thumbnail_url,
                    }
                )

            # Determine if there are more videos
            # If we got exactly the limit, there might be more
            has_more = len(videos) == limit
            next_cursor = str(start_index + len(videos)) if has_more else None

            # Try to get total video count (not always available)
            total_count = info.get("playlist_count")

            logger.info(
                "Fetched channel videos successfully",
                channel_id=channel_id,
                channel_name=channel_name,
                video_count=len(videos),
                has_more=has_more,
            )

            return {
                "youtube_channel_id": channel_id,
                "channel_name": channel_name,
                "total_video_count": total_count,
                "videos": videos,
                "next_cursor": next_cursor,
                "has_more": has_more,
            }

        except Exception as e:
            logger.error(
                "Failed to fetch channel videos",
                channel_url=channel_url,
                error=str(e),
            )
            raise ValueError(f"Failed to fetch channel: {e!s}") from e

    async def fetch_all_channel_video_ids(
        self,
        channel_url: str,
    ) -> list[str]:
        """Fetch all video IDs from a YouTube channel.

        Used for "ingest all" functionality. Fetches only video IDs
        without full metadata for efficiency.

        Args:
            channel_url: YouTube channel URL.

        Returns:
            List of YouTube video IDs.
        """
        import yt_dlp

        normalized_url = self.normalize_channel_url(channel_url)
        logger.info(
            "Fetching all channel video IDs",
            original_url=channel_url,
            normalized_url=normalized_url,
        )

        ydl_opts = {
            "skip_download": True,
            "quiet": True,
            "no_warnings": True,
            "extract_flat": True,
            "ignoreerrors": True,
            # No limit - get all videos
        }

        try:
            loop = asyncio.get_event_loop()
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = await loop.run_in_executor(
                    None, lambda: ydl.extract_info(normalized_url, download=False)
                )

            if not info:
                raise ValueError("Failed to extract channel information")

            entries = info.get("entries", []) or []
            video_ids = [
                entry.get("id") for entry in entries if entry and entry.get("id")
            ]

            logger.info(
                "Fetched all channel video IDs",
                video_count=len(video_ids),
            )

            return video_ids

        except Exception as e:
            logger.error(
                "Failed to fetch all channel video IDs",
                channel_url=channel_url,
                error=str(e),
            )
            raise ValueError(f"Failed to fetch channel: {e!s}") from e


# Singleton instance
_youtube_service: YouTubeService | None = None


def get_youtube_service() -> YouTubeService:
    """Get the YouTube service singleton.

    Returns:
        YouTubeService instance.
    """
    global _youtube_service
    if _youtube_service is None:
        _youtube_service = YouTubeService()
    return _youtube_service
