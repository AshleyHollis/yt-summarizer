"""Batch service for batch ingestion operations."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

try:
    from shared.db.models import Batch, BatchItem, Channel, Job, Video
    from shared.logging.config import get_logger
    from shared.queue.client import TRANSCRIBE_QUEUE, get_queue_client
    from shared.telemetry.config import inject_trace_context
except ImportError:
    from typing import Any

    Batch = Any
    BatchItem = Any
    Channel = Any
    Job = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)

    TRANSCRIBE_QUEUE = "transcribe-jobs"

    def get_queue_client():
        raise NotImplementedError("Queue client not available")
    
    def inject_trace_context(message):
        return message


from ..models.batch import (
    BatchDetailResponse,
    BatchItemStatus,
    BatchListResponse,
    BatchResponse,
    BatchRetryResponse,
    BatchStatus,
    CreateBatchRequest,
)
from ..models.batch import (
    BatchItem as BatchItemResponse,
)
from ..models.job import JobStage, JobStatus, JobType
from .channel_service import ChannelService
from .youtube_service import get_youtube_service

logger = get_logger(__name__)


class BatchService:
    """Service for batch ingestion operations."""

    def __init__(self, session: AsyncSession):
        """Initialize the batch service.

        Args:
            session: Database session.
        """
        self.session = session
        self.channel_service = ChannelService(session)
        self.youtube_service = get_youtube_service()

    async def create_batch(
        self,
        request: CreateBatchRequest,
        correlation_id: str,
    ) -> BatchResponse:
        """Create a batch for video ingestion.

        Args:
            request: Batch creation request.
            correlation_id: Request correlation ID.

        Returns:
            BatchResponse with batch info.
        """
        logger.info(
            "Creating batch",
            name=request.name,
            video_count=len(request.video_ids),
            ingest_all=request.ingest_all,
            channel_id=str(request.channel_id) if request.channel_id else None,
        )

        # Collect video IDs to ingest
        video_ids_to_ingest = list(request.video_ids)

        # If ingestAll is requested, fetch all video IDs from the channel
        if request.ingest_all and request.youtube_channel_id:
            logger.info("Fetching all channel videos for ingest_all")
            # Build channel URL from youtube_channel_id
            channel_url = f"https://www.youtube.com/channel/{request.youtube_channel_id}"
            all_video_ids = await self.youtube_service.fetch_all_channel_video_ids(
                channel_url
            )
            video_ids_to_ingest = all_video_ids
            logger.info(
                "Fetched all channel video IDs",
                count=len(video_ids_to_ingest),
            )

        if not video_ids_to_ingest:
            raise ValueError("No videos to ingest")

        # Get or create channel if provided
        channel: Channel | None = None
        if request.channel_id:
            channel = await self.channel_service.get_channel(request.channel_id)
        elif request.youtube_channel_id:
            # Try to find channel by YouTube ID
            result = await self.session.execute(
                select(Channel).where(
                    Channel.youtube_channel_id == request.youtube_channel_id
                )
            )
            channel = result.scalar_one_or_none()

        # Create batch record
        batch = Batch(
            channel_id=channel.channel_id if channel else None,
            name=request.name,
            total_count=len(video_ids_to_ingest),
            pending_count=len(video_ids_to_ingest),
            running_count=0,
            succeeded_count=0,
            failed_count=0,
        )
        self.session.add(batch)
        await self.session.flush()

        # Process each video
        for youtube_video_id in video_ids_to_ingest:
            try:
                await self._create_batch_item(
                    batch=batch,
                    youtube_video_id=youtube_video_id,
                    correlation_id=correlation_id,
                    channel=channel,
                )
            except Exception as e:
                logger.warning(
                    "Failed to create batch item",
                    youtube_video_id=youtube_video_id,
                    error=str(e),
                )
                # Continue with other videos

        await self.session.commit()

        logger.info(
            "Created batch",
            batch_id=str(batch.batch_id),
            total_count=batch.total_count,
        )

        return BatchResponse(
            id=batch.batch_id,
            name=batch.name or "",
            channel_name=channel.name if channel else None,
            status=self._compute_batch_status(batch),
            total_count=batch.total_count,
            pending_count=batch.pending_count,
            running_count=batch.running_count,
            succeeded_count=batch.succeeded_count,
            failed_count=batch.failed_count,
            created_at=batch.created_at,
            updated_at=batch.created_at,
        )

    async def _create_batch_item(
        self,
        batch: Batch,
        youtube_video_id: str,
        correlation_id: str,
        channel: Channel | None,
    ) -> None:
        """Create a batch item for a single video.

        Args:
            batch: Batch record.
            youtube_video_id: YouTube video ID.
            correlation_id: Request correlation ID.
            channel: Optional channel for the video.
        """
        # Check if video already exists
        result = await self.session.execute(
            select(Video).where(Video.youtube_video_id == youtube_video_id)
        )
        video = result.scalar_one_or_none()

        if video:
            # Video exists, just add to batch
            batch_item = BatchItem(
                batch_id=batch.batch_id,
                video_id=video.video_id,
                status="succeeded" if video.processing_status == "completed" else "pending",
            )
            self.session.add(batch_item)

            # Update batch counts if already completed
            if video.processing_status == "completed":
                batch.pending_count -= 1
                batch.succeeded_count += 1
            return

        # Fetch video metadata
        video_metadata = await self._fetch_video_metadata(youtube_video_id)

        # Use provided channel or get/create from metadata
        if channel is None:
            channel = await self.channel_service.get_or_create_channel(
                youtube_channel_id=video_metadata["channel"]["youtube_channel_id"],
                channel_name=video_metadata["channel"]["name"],
            )

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
        await self.session.flush()

        # Create batch item
        batch_item = BatchItem(
            batch_id=batch.batch_id,
            video_id=video.video_id,
            status="pending",
        )
        self.session.add(batch_item)

        # Create transcribe job
        job = Job(
            video_id=video.video_id,
            batch_id=batch.batch_id,
            job_type=JobType.TRANSCRIBE.value,
            stage=JobStage.QUEUED.value,
            status=JobStatus.PENDING.value,
            correlation_id=correlation_id,
        )
        self.session.add(job)
        await self.session.flush()

        # Queue the job
        try:
            queue_client = get_queue_client()
            queue_client.send_message(
                TRANSCRIBE_QUEUE,
                inject_trace_context({
                    "job_id": str(job.job_id),
                    "video_id": str(video.video_id),
                    "youtube_video_id": youtube_video_id,
                    "channel_name": channel.name,
                    "batch_id": str(batch.batch_id),
                    "correlation_id": correlation_id,
                }),
            )
        except Exception as e:
            logger.warning(
                "Failed to queue job",
                job_id=str(job.job_id),
                error=str(e),
            )

    async def _fetch_video_metadata(self, youtube_video_id: str) -> dict:
        """Fetch video metadata from YouTube using yt-dlp.

        Args:
            youtube_video_id: YouTube video ID.

        Returns:
            Dictionary with video metadata.
        """
        import asyncio

        import yt_dlp

        logger.info(
            "Fetching video metadata",
            youtube_video_id=youtube_video_id,
        )

        ydl_opts = {
            "skip_download": True,
            "quiet": True,
            "no_warnings": True,
            "extract_flat": False,
        }

        try:
            loop = asyncio.get_event_loop()
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = await loop.run_in_executor(
                    None,
                    lambda: ydl.extract_info(
                        f"https://www.youtube.com/watch?v={youtube_video_id}",
                        download=False,
                    ),
                )

            # Parse upload date
            upload_date_str = info.get("upload_date")
            if upload_date_str:
                publish_date = datetime.strptime(upload_date_str, "%Y%m%d")
            else:
                publish_date = datetime.utcnow()

            # Get best thumbnail
            thumbnails = info.get("thumbnails", [])
            thumbnail_url = None
            if thumbnails:
                sorted_thumbs = sorted(
                    thumbnails,
                    key=lambda t: (t.get("height", 0) or 0) * (t.get("width", 0) or 0),
                    reverse=True,
                )
                thumbnail_url = sorted_thumbs[0].get("url") if sorted_thumbs else None

            if not thumbnail_url:
                thumbnail_url = (
                    f"https://img.youtube.com/vi/{youtube_video_id}/maxresdefault.jpg"
                )

            channel_id = (
                info.get("channel_id") or info.get("uploader_id") or "UC_unknown"
            )
            channel_name = (
                info.get("channel") or info.get("uploader") or "Unknown Channel"
            )

            return {
                "title": info.get("title") or f"Video {youtube_video_id}",
                "description": info.get("description"),
                "duration": info.get("duration") or 0,
                "publish_date": publish_date,
                "thumbnail_url": thumbnail_url,
                "channel": {
                    "youtube_channel_id": channel_id,
                    "name": channel_name,
                    "thumbnail_url": info.get("channel_thumbnail_url"),
                },
            }

        except Exception as e:
            error_str = str(e).lower()
            
            # Check for specific error patterns that indicate video doesn't exist
            video_not_found_patterns = [
                "video unavailable",
                "private video",
                "video is unavailable",
                "this video has been removed",
                "this video is no longer available",
                "this video is private",
                "sign in to confirm your age",
                "video is not available",
                "unable to extract",
                "is not a valid url",
                "no video formats found",
            ]
            
            if any(pattern in error_str for pattern in video_not_found_patterns):
                logger.warning(
                    "Video not found on YouTube",
                    youtube_video_id=youtube_video_id,
                    error=str(e),
                )
                raise ValueError(f"Video not found or unavailable on YouTube: {youtube_video_id}")
            
            # For other errors, also raise to prevent creating bad data
            logger.warning(
                "Failed to fetch video metadata",
                youtube_video_id=youtube_video_id,
                error=str(e),
            )
            raise ValueError(f"Failed to verify video exists: {youtube_video_id} - {str(e)}")

    async def get_batches(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> BatchListResponse:
        """Get paginated list of batches.

        Args:
            page: Page number (1-indexed).
            page_size: Items per page.

        Returns:
            BatchListResponse with batch list.
        """
        offset = (page - 1) * page_size

        # Get total count
        count_result = await self.session.execute(select(func.count(Batch.batch_id)))
        total_count = count_result.scalar_one()

        # Get batches with channel info
        result = await self.session.execute(
            select(Batch)
            .options(selectinload(Batch.channel))
            .order_by(Batch.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        batches = result.scalars().all()

        return BatchListResponse(
            batches=[self._to_batch_response(b) for b in batches],
            total_count=total_count,
            page=page,
            page_size=page_size,
        )

    async def get_batch(self, batch_id: UUID) -> BatchDetailResponse | None:
        """Get batch details by ID.

        Args:
            batch_id: Batch ID.

        Returns:
            BatchDetailResponse or None if not found.
        """
        result = await self.session.execute(
            select(Batch)
            .options(
                selectinload(Batch.channel),
                selectinload(Batch.items).selectinload(BatchItem.video),
            )
            .where(Batch.batch_id == batch_id)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            return None

        items = [
            BatchItemResponse(
                id=item.batch_item_id,
                video_id=item.video_id,
                youtube_video_id=item.video.youtube_video_id if item.video else "",
                title=item.video.title if item.video else "",
                status=BatchItemStatus(item.status),
                error_message=item.video.error_message if item.video else None,
                created_at=item.created_at,
                updated_at=item.created_at,
            )
            for item in batch.items
        ]

        return BatchDetailResponse(
            id=batch.batch_id,
            name=batch.name or "",
            channel_name=batch.channel.name if batch.channel else None,
            status=self._compute_batch_status(batch),
            total_count=batch.total_count,
            pending_count=batch.pending_count,
            running_count=batch.running_count,
            succeeded_count=batch.succeeded_count,
            failed_count=batch.failed_count,
            created_at=batch.created_at,
            updated_at=batch.created_at,
            items=items,
        )

    async def retry_failed_items(
        self,
        batch_id: UUID,
        correlation_id: str,
    ) -> BatchRetryResponse:
        """Retry all failed items in a batch.

        Args:
            batch_id: Batch ID.
            correlation_id: Request correlation ID.

        Returns:
            BatchRetryResponse with retry info.

        Raises:
            ValueError: If batch not found.
        """
        result = await self.session.execute(
            select(Batch)
            .options(
                selectinload(Batch.items)
                .selectinload(BatchItem.video)
                .selectinload(Video.channel),
                selectinload(Batch.channel),
            )
            .where(Batch.batch_id == batch_id)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        # Find failed items
        failed_items = [item for item in batch.items if item.status == "failed"]

        if not failed_items:
            return BatchRetryResponse(
                batch_id=batch_id,
                retried_count=0,
                message="No failed items to retry",
            )

        # Reset failed items to pending and queue jobs
        retried_count = 0
        for item in failed_items:
            item.status = "pending"
            batch.failed_count -= 1
            batch.pending_count += 1

            # Reset video status
            if item.video:
                item.video.processing_status = "pending"
                item.video.error_message = None

                # Create new job
                job = Job(
                    video_id=item.video_id,
                    batch_id=batch_id,
                    job_type=JobType.TRANSCRIBE.value,
                    stage=JobStage.QUEUED.value,
                    status=JobStatus.PENDING.value,
                    correlation_id=correlation_id,
                )
                self.session.add(job)
                await self.session.flush()

                # Queue job
                try:
                    # Get channel name for blob storage path
                    channel_name = "unknown-channel"
                    if item.video.channel:
                        channel_name = item.video.channel.name
                    elif batch.channel:
                        channel_name = batch.channel.name
                    
                    queue_client = get_queue_client()
                    queue_client.send_message(
                        TRANSCRIBE_QUEUE,
                        inject_trace_context({
                            "job_id": str(job.job_id),
                            "video_id": str(item.video_id),
                            "youtube_video_id": item.video.youtube_video_id,
                            "channel_name": channel_name,
                            "batch_id": str(batch_id),
                            "correlation_id": correlation_id,
                        }),
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to queue retry job",
                        job_id=str(job.job_id),
                        error=str(e),
                    )

            retried_count += 1

        await self.session.commit()

        return BatchRetryResponse(
            batch_id=batch_id,
            retried_count=retried_count,
            message=f"Queued {retried_count} videos for retry",
        )

    async def retry_single_item(
        self,
        batch_id: UUID,
        video_id: UUID,
        correlation_id: str,
    ) -> BatchRetryResponse:
        """Retry a single failed item in a batch.

        Args:
            batch_id: Batch ID.
            video_id: Video ID to retry.
            correlation_id: Request correlation ID.

        Returns:
            BatchRetryResponse with retry info.

        Raises:
            ValueError: If batch or item not found.
        """
        result = await self.session.execute(
            select(Batch)
            .options(
                selectinload(Batch.items)
                .selectinload(BatchItem.video)
                .selectinload(Video.channel),
                selectinload(Batch.channel),
            )
            .where(Batch.batch_id == batch_id)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        # Find the specific item
        item = next(
            (i for i in batch.items if i.video_id == video_id),
            None,
        )

        if not item:
            raise ValueError("Video not found in batch")

        if item.status != "failed":
            return BatchRetryResponse(
                batch_id=batch_id,
                retried_count=0,
                message="Video is not in failed state",
            )

        # Reset item to pending
        item.status = "pending"
        batch.failed_count -= 1
        batch.pending_count += 1

        # Reset video status
        if item.video:
            item.video.processing_status = "pending"
            item.video.error_message = None

            # Create new job
            job = Job(
                video_id=item.video_id,
                batch_id=batch_id,
                job_type=JobType.TRANSCRIBE.value,
                stage=JobStage.QUEUED.value,
                status=JobStatus.PENDING.value,
                correlation_id=correlation_id,
            )
            self.session.add(job)
            await self.session.flush()

            # Queue job
            try:
                # Get channel name for blob storage path
                channel_name = "unknown-channel"
                if item.video.channel:
                    channel_name = item.video.channel.name
                elif batch.channel:
                    channel_name = batch.channel.name
                
                queue_client = get_queue_client()
                queue_client.send_message(
                    TRANSCRIBE_QUEUE,
                    inject_trace_context({
                        "job_id": str(job.job_id),
                        "video_id": str(item.video_id),
                        "youtube_video_id": item.video.youtube_video_id,
                        "channel_name": channel_name,
                        "batch_id": str(batch_id),
                        "correlation_id": correlation_id,
                    }),
                )
            except Exception as e:
                logger.warning(
                    "Failed to queue retry job",
                    job_id=str(job.job_id),
                    error=str(e),
                )

        await self.session.commit()

        return BatchRetryResponse(
            batch_id=batch_id,
            retried_count=1,
            message="Video queued for retry",
        )

    def _to_batch_response(self, batch: Batch) -> BatchResponse:
        """Convert Batch model to response."""
        return BatchResponse(
            id=batch.batch_id,
            name=batch.name or "",
            channel_name=batch.channel.name if batch.channel else None,
            status=self._compute_batch_status(batch),
            total_count=batch.total_count,
            pending_count=batch.pending_count,
            running_count=batch.running_count,
            succeeded_count=batch.succeeded_count,
            failed_count=batch.failed_count,
            created_at=batch.created_at,
            updated_at=batch.created_at,
        )

    def _compute_batch_status(self, batch: Batch) -> BatchStatus:
        """Compute overall batch status from counts."""
        if batch.pending_count == batch.total_count:
            return BatchStatus.PENDING
        elif batch.running_count > 0:
            return BatchStatus.RUNNING
        elif batch.failed_count > 0 and batch.succeeded_count + batch.failed_count == batch.total_count:
            return BatchStatus.FAILED
        elif batch.succeeded_count == batch.total_count:
            return BatchStatus.COMPLETED
        elif batch.pending_count > 0 or batch.running_count > 0:
            return BatchStatus.RUNNING
        else:
            return BatchStatus.COMPLETED
