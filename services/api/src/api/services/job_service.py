"""Job service for handling job operations."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.models import Job, JobHistory, Video
    from shared.logging.config import get_logger
    from shared.queue.client import get_queue_client
except ImportError:
    from typing import Any

    Job = Any
    JobHistory = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)

    def get_queue_client():
        raise NotImplementedError("Queue client not available")


from ..models.base import PaginationMeta
from ..models.job import (
    ETAInfo,
    JobListFilters,
    JobListResponse,
    JobResponse,
    JobStage,
    JobStatus,
    JobSummaryResponse,
    JobType,
    RetryJobResponse,
    StageEstimate,
    StageHistoryItem,
    VideoJobsProgress,
    VideoProcessingHistory,
)
from .stats_service import StatsService

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
                retry_count=job.retry_count,
                created_at=job.created_at,
                updated_at=job.updated_at,
                next_retry_at=job.next_retry_at,
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

        # Calculate ETA for in-progress videos
        eta_info = None
        current_stage_name = None
        
        if overall_status in ("pending", "processing"):
            # Find the current running job
            current_job = next(
                (j for j in jobs if j.status == JobStatus.RUNNING.value),
                None
            )
            current_job_type = current_job.job_type if current_job else None
            current_job_started = current_job.started_at if current_job else None
            
            # Find the FIRST job's started_at for UI anchor (not current job)
            # This ensures the countdown doesn't reset when stages change
            first_job_started = None
            for job in jobs:
                if job.started_at:
                    if first_job_started is None or job.started_at < first_job_started:
                        first_job_started = job.started_at
            
            # Human-readable stage names
            stage_names = {
                "transcribe": "Extracting Transcript",
                "summarize": "Generating Summary",
                "embed": "Creating Embeddings",
                "build_relationships": "Finding Related Videos",
            }
            
            if current_job_type:
                current_stage_name = stage_names.get(current_job_type, current_job_type)
            
            try:
                stats_service = StatsService(self.session)
                eta_data = await stats_service.calculate_eta(
                    video_id=video_id,
                    current_job_type=current_job_type,
                    current_job_started_at=current_job_started,
                    first_job_started_at=first_job_started,
                )
                
                eta_info = ETAInfo(
                    estimated_seconds_remaining=eta_data["estimated_seconds_remaining"],
                    estimated_total_seconds=eta_data["estimated_total_seconds"],
                    estimated_ready_at=eta_data["estimated_ready_at"],
                    elapsed_seconds=eta_data["elapsed_seconds"],
                    processing_started_at=eta_data["processing_started_at"],
                    queue_position=eta_data["queue_position"],
                    total_in_queue=eta_data["total_in_queue"],
                    videos_ahead=eta_data["videos_ahead"],
                    queue_wait_seconds=eta_data["queue_wait_seconds"],
                    stages_remaining=[
                        StageEstimate(
                            stage=s["stage"],
                            estimated_seconds=s["estimated_seconds"],
                        )
                        for s in eta_data["stages_remaining"]
                    ],
                )
            except Exception as e:
                logger.warning("Failed to calculate ETA", error=str(e))
                eta_info = None

        return VideoJobsProgress(
            video_id=video_id,
            overall_status=overall_status,
            overall_progress=overall_progress,
            jobs=items,
            eta=eta_info,
            current_stage_name=current_stage_name,
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

    async def get_video_processing_history(self, video_id: UUID) -> VideoProcessingHistory | None:
        """Get the complete processing history for a video.

        Shows actual vs estimated times for each stage, variance analysis,
        and comparison to average processing times.

        Args:
            video_id: Video ID.

        Returns:
            VideoProcessingHistory or None if video not found.
        """
        # Get video
        video_result = await self.session.execute(
            select(Video).where(Video.video_id == video_id)
        )
        video = video_result.scalar_one_or_none()
        if not video:
            return None

        # Get jobs for this video
        jobs_result = await self.session.execute(
            select(Job)
            .where(Job.video_id == video_id)
            .order_by(Job.created_at.asc())
        )
        jobs = jobs_result.scalars().all()

        # Get average times for estimates (scaled by video duration for transcribe)
        stats_service = StatsService(self.session)
        averages = await stats_service.get_all_average_processing_times(
            video_duration_seconds=video.duration
        )
        
        # Get enforced delay estimates
        enforced_delays = await stats_service.get_average_enforced_delays()

        # Human-readable stage labels
        stage_labels = {
            "transcribe": "Extracting Transcript",
            "summarize": "Generating Summary",
            "embed": "Creating Embeddings",
            "build_relationships": "Finding Related Videos",
        }

        # Build stage history
        stages = []
        total_actual = 0.0
        total_wait = 0.0
        total_estimated = 0.0
        total_estimated_delay = 0.0
        total_estimated_wait = 0.0  # From first job (transcribe)
        stages_completed = 0
        stages_failed = 0
        total_retries = 0
        first_started = None
        last_completed = None
        submitted_at = video.created_at if video else None

        for job in jobs:
            job_type = job.job_type
            estimated = averages.get(job_type, 30.0)
            estimated_delay = enforced_delays.get(job_type, 0.0)
            total_estimated += estimated
            total_estimated_delay += estimated_delay

            # Get estimated wait from the first job (transcribe) where queue wait applies
            estimated_wait_for_stage = None
            if job_type == "transcribe" and hasattr(job, 'estimated_wait_seconds'):
                estimated_wait_for_stage = job.estimated_wait_seconds
                if estimated_wait_for_stage:
                    total_estimated_wait = estimated_wait_for_stage

            # Calculate wait time (time from queued to started)
            wait_seconds = None
            if job.created_at and job.started_at:
                wait_seconds = (job.started_at - job.created_at).total_seconds()
                total_wait += wait_seconds

            # Calculate actual time
            actual = None
            variance = None
            variance_pct = None

            if job.started_at and job.completed_at:
                actual = (job.completed_at - job.started_at).total_seconds()
                total_actual += actual
                # Variance compares actual to estimated (NOT estimated + delay)
                # because the estimated_seconds from historical avg already INCLUDES
                # the enforced delay (it's based on job duration which includes sleep time)
                variance = actual - estimated
                variance_pct = ((actual - estimated) / estimated * 100) if estimated > 0 else None

                # Track first/last times
                if first_started is None or job.started_at < first_started:
                    first_started = job.started_at
                if last_completed is None or job.completed_at > last_completed:
                    last_completed = job.completed_at

            # Track stats
            if job.status == "succeeded":
                stages_completed += 1
            elif job.status == "failed":
                stages_failed += 1
            total_retries += job.retry_count

            stages.append(
                StageHistoryItem(
                    stage=job_type,
                    stage_label=stage_labels.get(job_type, job_type),
                    status=job.status,
                    queued_at=job.created_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    wait_seconds=wait_seconds,
                    estimated_wait_seconds=estimated_wait_for_stage,
                    enforced_delay_seconds=None,  # TODO: Get from JobHistory when recorded
                    actual_seconds=actual,
                    estimated_seconds=estimated,
                    estimated_delay_seconds=estimated_delay,
                    variance_seconds=variance,
                    variance_percent=variance_pct,
                    retry_count=job.retry_count,
                )
            )

        # Calculate total variance (comparing actual to estimated only)
        # Note: estimated_seconds already INCLUDES enforced delays because it's
        # derived from historical job durations which include sleep time
        total_variance = None
        faster_than_average = None
        if total_actual > 0:
            total_variance = total_actual - total_estimated
            faster_than_average = total_actual < total_estimated

        # Calculate percentile (rough estimate based on variance)
        percentile = None
        if total_variance is not None and total_estimated > 0:
            # Simple percentile: 50 = average, higher = faster
            # Each 10% faster/slower = +/- 10 percentile points
            variance_pct = (total_variance / total_estimated) * 100
            percentile = max(1, min(99, 50 - int(variance_pct)))

        # Calculate total elapsed time (wall-clock from submission to completion)
        total_elapsed = None
        if submitted_at and last_completed:
            total_elapsed = (last_completed - submitted_at).total_seconds()

        return VideoProcessingHistory(
            video_id=video_id,
            video_title=video.title,
            video_duration_seconds=video.duration,
            processing_status=video.processing_status,
            submitted_at=submitted_at,
            first_job_started_at=first_started,
            last_job_completed_at=last_completed,
            total_wait_seconds=total_wait if total_wait > 0 else None,
            total_estimated_wait_seconds=total_estimated_wait if total_estimated_wait > 0 else None,
            total_enforced_delay_seconds=None,  # TODO: Get actual from JobHistory when recorded
            total_actual_seconds=total_actual if total_actual > 0 else None,
            total_estimated_seconds=total_estimated,
            total_estimated_delay_seconds=total_estimated_delay,
            total_elapsed_seconds=total_elapsed,
            total_variance_seconds=total_variance,
            stages=stages,
            stages_completed=stages_completed,
            stages_failed=stages_failed,
            total_retries=total_retries,
            faster_than_average=faster_than_average,
            percentile=percentile,
        )
