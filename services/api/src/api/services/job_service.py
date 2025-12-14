"""Job service for handling job operations."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.models import Job, Video
    from shared.logging.config import get_logger
    from shared.queue.client import get_queue_client
except ImportError:
    from typing import Any

    Job = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)

    def get_queue_client():
        raise NotImplementedError("Queue client not available")


from ..models.base import PaginationMeta
from ..models.job import (
    JobListFilters,
    JobListResponse,
    JobResponse,
    JobStage,
    JobStatus,
    JobSummaryResponse,
    JobType,
    RetryJobResponse,
    VideoJobsProgress,
)

logger = get_logger(__name__)


class JobService:
    """Service for job operations."""

    def __init__(self, session: AsyncSession):
        """Initialize the job service.

        Args:
            session: Database session.
        """
        self.session = session

    async def get_job(self, job_id: UUID) -> JobResponse | None:
        """Get a job by ID.

        Args:
            job_id: Job ID.

        Returns:
            JobResponse or None if not found.
        """
        result = await self.session.execute(
            select(Job).where(Job.job_id == job_id)
        )
        job = result.scalar_one_or_none()

        if not job:
            return None

        return JobResponse(
            job_id=job.job_id,
            video_id=job.video_id,
            batch_id=job.batch_id,
            job_type=JobType(job.job_type),
            stage=JobStage(job.stage),
            status=JobStatus(job.status),
            progress=job.progress,
            error_message=job.error_message,
            retry_count=job.retry_count,
            max_retries=job.max_retries,
            correlation_id=job.correlation_id,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at,
            updated_at=job.updated_at,
        )

    async def list_jobs(
        self,
        filters: JobListFilters,
        page: int = 1,
        per_page: int = 20,
    ) -> JobListResponse:
        """List jobs with filters.

        Args:
            filters: Filter criteria.
            page: Page number (1-indexed).
            per_page: Items per page.

        Returns:
            Paginated list of jobs.
        """
        # Build query
        query = select(Job)

        if filters.video_id:
            query = query.where(Job.video_id == filters.video_id)
        if filters.batch_id:
            query = query.where(Job.batch_id == filters.batch_id)
        if filters.job_type:
            query = query.where(Job.job_type == filters.job_type.value)
        if filters.status:
            query = query.where(Job.status == filters.status.value)
        if filters.stage:
            query = query.where(Job.stage == filters.stage.value)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination
        query = query.order_by(Job.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        result = await self.session.execute(query)
        jobs = result.scalars().all()

        items = [
            JobSummaryResponse(
                job_id=job.job_id,
                video_id=job.video_id,
                job_type=JobType(job.job_type),
                stage=JobStage(job.stage),
                status=JobStatus(job.status),
                progress=job.progress,
                error_message=job.error_message,
                created_at=job.created_at,
            )
            for job in jobs
        ]

        return JobListResponse(
            items=items,
            pagination=PaginationMeta.create(page, per_page, total),
        )

    async def get_video_jobs_progress(self, video_id: UUID) -> VideoJobsProgress | None:
        """Get progress of all jobs for a video.

        Args:
            video_id: Video ID.

        Returns:
            VideoJobsProgress or None if video not found.
        """
        # Check video exists
        video_result = await self.session.execute(
            select(Video).where(Video.video_id == video_id)
        )
        video = video_result.scalar_one_or_none()
        if not video:
            return None

        # Get all jobs for this video
        result = await self.session.execute(
            select(Job)
            .where(Job.video_id == video_id)
            .order_by(Job.created_at.asc())
        )
        jobs = result.scalars().all()

        items = [
            JobSummaryResponse(
                job_id=job.job_id,
                video_id=job.video_id,
                job_type=JobType(job.job_type),
                stage=JobStage(job.stage),
                status=JobStatus(job.status),
                progress=job.progress,
                error_message=job.error_message,
                created_at=job.created_at,
            )
            for job in jobs
        ]

        # Calculate overall progress
        if not items:
            overall_progress = 0
            overall_status = "pending"
        else:
            succeeded = sum(1 for j in items if j.status == JobStatus.SUCCEEDED)
            failed = sum(1 for j in items if j.status == JobStatus.FAILED)
            running = sum(1 for j in items if j.status == JobStatus.RUNNING)

            # Expected 4 stages for complete processing
            expected_stages = 4
            overall_progress = int((succeeded / expected_stages) * 100)

            if failed > 0:
                overall_status = "failed"
            elif running > 0:
                overall_status = "processing"
            elif succeeded >= expected_stages:
                overall_status = "completed"
            else:
                overall_status = "processing"

        return VideoJobsProgress(
            video_id=video_id,
            overall_status=overall_status,
            overall_progress=overall_progress,
            jobs=items,
        )

    async def retry_job(
        self,
        job_id: UUID,
        reset_retries: bool,
        correlation_id: str,
    ) -> RetryJobResponse | None:
        """Retry a failed job.

        Args:
            job_id: Job ID.
            reset_retries: Whether to reset retry count.
            correlation_id: Request correlation ID.

        Returns:
            RetryJobResponse or None if job not found.
        """
        result = await self.session.execute(
            select(Job).where(Job.job_id == job_id)
        )
        job = result.scalar_one_or_none()

        if not job:
            return None

        # Only allow retry of failed jobs
        if job.status != JobStatus.FAILED.value and job.stage != JobStage.DEAD_LETTERED.value:
            return RetryJobResponse(
                job_id=job.job_id,
                status=JobStatus(job.status),
                message=f"Job cannot be retried (current status: {job.status})",
            )

        # Reset job state
        job.stage = JobStage.QUEUED.value
        job.status = JobStatus.PENDING.value
        job.error_message = None
        job.started_at = None
        job.completed_at = None

        if reset_retries:
            job.retry_count = 0

        job.correlation_id = correlation_id

        # Queue the job
        queue_name = self._get_queue_for_job_type(JobType(job.job_type))
        try:
            queue_client = get_queue_client()

            # Get video info
            video_result = await self.session.execute(
                select(Video).where(Video.video_id == job.video_id)
            )
            video = video_result.scalar_one_or_none()

            queue_client.send_message(
                queue_name,
                {
                    "job_id": str(job.job_id),
                    "video_id": str(job.video_id),
                    "youtube_video_id": video.youtube_video_id if video else "",
                    "correlation_id": correlation_id,
                    "retry_count": job.retry_count,
                },
            )
            logger.info("Queued retry job", job_id=str(job.job_id))
        except Exception as e:
            logger.warning("Failed to queue job", error=str(e))

        await self.session.commit()

        return RetryJobResponse(
            job_id=job.job_id,
            status=JobStatus.PENDING,
            message="Job queued for retry",
        )

    async def update_job_status(
        self,
        job_id: UUID,
        stage: JobStage,
        status: JobStatus,
        progress: int | None = None,
        error_message: str | None = None,
    ) -> JobResponse | None:
        """Update job status (called by workers).

        Args:
            job_id: Job ID.
            stage: New stage.
            status: New status.
            progress: Progress percentage.
            error_message: Error message if failed.

        Returns:
            Updated JobResponse or None if not found.
        """
        result = await self.session.execute(
            select(Job).where(Job.job_id == job_id)
        )
        job = result.scalar_one_or_none()

        if not job:
            return None

        job.stage = stage.value
        job.status = status.value
        job.progress = progress
        job.error_message = error_message

        if stage == JobStage.RUNNING and job.started_at is None:
            job.started_at = datetime.utcnow()

        if stage in (JobStage.COMPLETED, JobStage.FAILED, JobStage.DEAD_LETTERED):
            job.completed_at = datetime.utcnow()

        await self.session.commit()

        return await self.get_job(job_id)

    def _get_queue_for_job_type(self, job_type: JobType) -> str:
        """Get the queue name for a job type."""
        queue_map = {
            JobType.TRANSCRIBE: "transcribe-jobs",
            JobType.SUMMARIZE: "summarize-jobs",
            JobType.EMBED: "embed-jobs",
            JobType.BUILD_RELATIONSHIPS: "relationships-jobs",
        }
        return queue_map.get(job_type, "transcribe-jobs")
