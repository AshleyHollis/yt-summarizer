"""Video service for handling video submission and retrieval."""

import re
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Import shared modules
try:
    from shared.db.models import Channel, Job, Video
    from shared.logging.config import get_logger
    from shared.queue.client import TRANSCRIBE_QUEUE, get_queue_client
except ImportError:
    # Fallback for development
    from typing import Any

    Channel = Any
    Job = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)

    TRANSCRIBE_QUEUE = "transcribe-jobs"

    def get_queue_client():
        raise NotImplementedError("Queue client not available")


from ..models.job import JobStage, JobStatus, JobType
from ..models.video import (
    ChannelSummary,
    ProcessingStatus,
    SubmitVideoResponse,
    VideoResponse,
    extract_youtube_video_id,
)

logger = get_logger(__name__)


class VideoService:
    """Service for video operations."""

    def __init__(self, session: AsyncSession):
        """Initialize the video service.

        Args:
            session: Database session.
        """
        self.session = session

    async def submit_video(
        self,
        url: str,
        correlation_id: str,
    ) -> SubmitVideoResponse:
        """Submit a video for processing.

        Args:
            url: YouTube video URL.
            correlation_id: Request correlation ID.

        Returns:
            SubmitVideoResponse with video and job IDs.

        Raises:
            ValueError: If URL is invalid or video already exists.
        """
        # Extract video ID from URL
        youtube_video_id = extract_youtube_video_id(url)
        if not youtube_video_id:
            raise ValueError("Invalid YouTube URL")

        # Check if video already exists
        existing = await self.session.execute(
            select(Video).where(Video.youtube_video_id == youtube_video_id)
        )
        existing_video = existing.scalar_one_or_none()

        if existing_video:
            # Return existing video info
            # Get the latest job for this video
            job_result = await self.session.execute(
                select(Job)
                .where(Job.video_id == existing_video.video_id)
                .order_by(Job.created_at.desc())
                .limit(1)
            )
            latest_job = job_result.scalar_one_or_none()

            return SubmitVideoResponse(
                video_id=existing_video.video_id,
                youtube_video_id=existing_video.youtube_video_id,
                job_id=latest_job.job_id if latest_job else existing_video.video_id,
                status=ProcessingStatus(existing_video.processing_status),
                message="Video already exists in the system",
            )

        # Fetch video metadata from YouTube
        video_metadata = await self._fetch_video_metadata(youtube_video_id)

        # Get or create channel
        channel = await self._get_or_create_channel(video_metadata["channel"])

        # Create video record
        video = Video(
            youtube_video_id=youtube_video_id,
            channel_id=channel.channel_id,
            title=video_metadata["title"],
            description=video_metadata.get("description"),
            duration=video_metadata["duration"],
            publish_date=video_metadata["publish_date"],
            thumbnail_url=video_metadata.get("thumbnail_url"),
            processing_status="pending",
        )
        self.session.add(video)
        
        # Handle race condition: if video was inserted by another request
        # between our check and insert, re-query and return existing
        try:
            await self.session.flush()  # Get video_id
        except IntegrityError:
            # Rollback the failed transaction and re-query
            await self.session.rollback()
            existing = await self.session.execute(
                select(Video).where(Video.youtube_video_id == youtube_video_id)
            )
            existing_video = existing.scalar_one_or_none()
            
            if existing_video:
                # Get the latest job for this video
                job_result = await self.session.execute(
                    select(Job)
                    .where(Job.video_id == existing_video.video_id)
                    .order_by(Job.created_at.desc())
                    .limit(1)
                )
                latest_job = job_result.scalar_one_or_none()

                return SubmitVideoResponse(
                    video_id=existing_video.video_id,
                    youtube_video_id=existing_video.youtube_video_id,
                    job_id=latest_job.job_id if latest_job else existing_video.video_id,
                    status=ProcessingStatus(existing_video.processing_status),
                    message="Video already exists in the system",
                )
            raise  # Re-raise if we still can't find it

        # Create initial transcribe job
        job = Job(
            video_id=video.video_id,
            job_type=JobType.TRANSCRIBE.value,
            stage=JobStage.QUEUED.value,
            status=JobStatus.PENDING.value,
            correlation_id=correlation_id,
        )
        self.session.add(job)
        await self.session.flush()  # Get job_id

        # Queue the job
        try:
            queue_client = get_queue_client()
            queue_client.send_message(
                TRANSCRIBE_QUEUE,
                {
                    "job_id": str(job.job_id),
                    "video_id": str(video.video_id),
                    "youtube_video_id": youtube_video_id,
                    "correlation_id": correlation_id,
                },
            )
            logger.info(
                "Queued transcribe job",
                job_id=str(job.job_id),
                video_id=str(video.video_id),
            )
        except Exception as e:
            logger.warning(
                "Failed to queue job (queue may not be available)",
                error=str(e),
            )

        await self.session.commit()

        return SubmitVideoResponse(
            video_id=video.video_id,
            youtube_video_id=youtube_video_id,
            job_id=job.job_id,
            status=ProcessingStatus.PENDING,
            message="Video submitted for processing",
        )

    async def get_video(self, video_id: UUID) -> VideoResponse | None:
        """Get a video by ID.

        Args:
            video_id: Video ID.

        Returns:
            VideoResponse or None if not found.
        """
        result = await self.session.execute(
            select(Video)
            .options(selectinload(Video.channel))
            .where(Video.video_id == video_id)
        )
        video = result.scalar_one_or_none()

        if not video:
            return None

        channel_summary = None
        if video.channel:
            channel_summary = ChannelSummary(
                channel_id=video.channel.channel_id,
                youtube_channel_id=video.channel.youtube_channel_id,
                name=video.channel.name,
                thumbnail_url=video.channel.thumbnail_url,
            )

        # Generate content URLs if video is completed
        transcript_url = None
        summary_url = None
        if video.processing_status == "completed":
            transcript_url = f"/api/v1/videos/{video.video_id}/transcript"
            summary_url = f"/api/v1/videos/{video.video_id}/summary"

        return VideoResponse(
            video_id=video.video_id,
            youtube_video_id=video.youtube_video_id,
            title=video.title,
            description=video.description,
            duration=video.duration,
            publish_date=video.publish_date,
            thumbnail_url=video.thumbnail_url,
            processing_status=ProcessingStatus(video.processing_status),
            error_message=video.error_message,
            channel=channel_summary,
            transcript_url=transcript_url,
            summary_url=summary_url,
            created_at=video.created_at,
            updated_at=video.updated_at,
        )

    async def get_video_by_youtube_id(self, youtube_video_id: str) -> VideoResponse | None:
        """Get a video by YouTube video ID.

        Args:
            youtube_video_id: YouTube video ID.

        Returns:
            VideoResponse or None if not found.
        """
        result = await self.session.execute(
            select(Video)
            .options(selectinload(Video.channel))
            .where(Video.youtube_video_id == youtube_video_id)
        )
        video = result.scalar_one_or_none()

        if not video:
            return None

        return await self.get_video(video.video_id)

    async def reprocess_video(
        self,
        video_id: UUID,
        stages: list[str] | None,
        correlation_id: str,
    ) -> SubmitVideoResponse:
        """Reprocess a video.

        Args:
            video_id: Video ID.
            stages: Specific stages to reprocess, or None for all.
            correlation_id: Request correlation ID.

        Returns:
            SubmitVideoResponse with new job ID.

        Raises:
            ValueError: If video not found.
        """
        result = await self.session.execute(
            select(Video).where(Video.video_id == video_id)
        )
        video = result.scalar_one_or_none()

        if not video:
            raise ValueError("Video not found")

        # Determine which stage to start from
        start_stage = JobType.TRANSCRIBE
        if stages:
            stage_order = [JobType.TRANSCRIBE, JobType.SUMMARIZE, JobType.EMBED, JobType.BUILD_RELATIONSHIPS]
            for stage in stage_order:
                if stage.value in stages:
                    start_stage = stage
                    break

        # Update video status
        video.processing_status = "processing"
        video.error_message = None

        # Create new job for the starting stage
        job = Job(
            video_id=video.video_id,
            job_type=start_stage.value,
            stage=JobStage.QUEUED.value,
            status=JobStatus.PENDING.value,
            correlation_id=correlation_id,
        )
        self.session.add(job)
        await self.session.flush()

        # Queue the job
        queue_name = self._get_queue_for_job_type(start_stage)
        try:
            queue_client = get_queue_client()
            queue_client.send_message(
                queue_name,
                {
                    "job_id": str(job.job_id),
                    "video_id": str(video.video_id),
                    "youtube_video_id": video.youtube_video_id,
                    "correlation_id": correlation_id,
                },
            )
        except Exception as e:
            logger.warning("Failed to queue job", error=str(e))

        await self.session.commit()

        return SubmitVideoResponse(
            video_id=video.video_id,
            youtube_video_id=video.youtube_video_id,
            job_id=job.job_id,
            status=ProcessingStatus.PROCESSING,
            message=f"Video reprocessing started from {start_stage.value}",
        )

    async def _fetch_video_metadata(self, youtube_video_id: str) -> dict:
        """Fetch video metadata from YouTube.

        Args:
            youtube_video_id: YouTube video ID.

        Returns:
            Dictionary with video metadata.
        """
        # TODO: Implement actual YouTube API call using yt-dlp
        # For now, return placeholder data
        return {
            "title": f"Video {youtube_video_id}",
            "description": None,
            "duration": 0,
            "publish_date": datetime.utcnow(),
            "thumbnail_url": f"https://img.youtube.com/vi/{youtube_video_id}/maxresdefault.jpg",
            "channel": {
                "youtube_channel_id": "UC_placeholder",
                "name": "Unknown Channel",
                "thumbnail_url": None,
            },
        }

    async def _get_or_create_channel(self, channel_data: dict) -> Channel:
        """Get or create a channel record.

        Args:
            channel_data: Channel metadata.

        Returns:
            Channel instance.
        """
        result = await self.session.execute(
            select(Channel).where(
                Channel.youtube_channel_id == channel_data["youtube_channel_id"]
            )
        )
        channel = result.scalar_one_or_none()

        if channel:
            return channel

        channel = Channel(
            youtube_channel_id=channel_data["youtube_channel_id"],
            name=channel_data["name"],
            thumbnail_url=channel_data.get("thumbnail_url"),
        )
        self.session.add(channel)
        await self.session.flush()

        return channel

    def _get_queue_for_job_type(self, job_type: JobType) -> str:
        """Get the queue name for a job type."""
        queue_map = {
            JobType.TRANSCRIBE: "transcribe-jobs",
            JobType.SUMMARIZE: "summarize-jobs",
            JobType.EMBED: "embed-jobs",
            JobType.BUILD_RELATIONSHIPS: "relationships-jobs",
        }
        return queue_map.get(job_type, "transcribe-jobs")
