"""Recovery service for automatic self-healing of stuck/failed video processing jobs.

Implements three recovery strategies:
1. Dead-letter recovery: Retry jobs that exhausted retries (with auto-recovery cap)
2. Orphan detection: Find videos stuck in "processing" with no active jobs
3. Stale job cleanup: Mark jobs stuck in "running" for too long as failed
"""

from datetime import datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import and_, func, not_, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.models import Job, Video
    from shared.logging.config import get_logger
    from shared.queue.client import get_queue_client
    from shared.telemetry.config import inject_trace_context
except ImportError:
    from typing import Any

    Job = Any
    Video = Any

    def get_logger(name):
        import logging

        return logging.getLogger(name)

    def get_queue_client():
        raise NotImplementedError("Queue client not available")

    def inject_trace_context(message):
        return message


logger = get_logger(__name__)

# Pipeline stage ordering
PIPELINE_STAGES = ["transcribe", "summarize", "embed", "build_relationships"]

QUEUE_MAP = {
    "transcribe": "transcribe-jobs",
    "summarize": "summarize-jobs",
    "embed": "embed-jobs",
    "build_relationships": "relationships-jobs",
}

# Max number of automatic recovery attempts per job before giving up
MAX_AUTO_RECOVERIES = 3

# Jobs stuck in "running" longer than this are considered stale
STALE_JOB_THRESHOLD_MINUTES = 15


class RecoveryAction(BaseModel):
    """A single recovery action taken."""

    action: str = Field(description="Type of recovery action")
    job_id: UUID | None = Field(default=None, description="Job ID affected")
    video_id: UUID = Field(description="Video ID affected")
    job_type: str = Field(description="Job type")
    detail: str = Field(description="Description of action taken")


class RecoveryResult(BaseModel):
    """Result of a recovery sweep."""

    dead_letter_recoveries: int = Field(default=0, description="Dead-lettered jobs retried")
    orphan_recoveries: int = Field(default=0, description="Orphaned videos re-queued")
    stale_cleanups: int = Field(default=0, description="Stale running jobs failed")
    skipped: int = Field(default=0, description="Jobs skipped (max auto-recoveries reached)")
    errors: int = Field(default=0, description="Errors during recovery")
    actions: list[RecoveryAction] = Field(default_factory=list, description="Actions taken")


class RecoveryService:
    """Service for automatic recovery of stuck/failed video processing."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def run_recovery_sweep(self, correlation_id: str) -> RecoveryResult:
        """Run a complete recovery sweep across all three strategies."""
        result = RecoveryResult()

        logger.info("Starting recovery sweep", correlation_id=correlation_id)

        await self._recover_dead_lettered_jobs(result, correlation_id)
        await self._recover_orphaned_videos(result, correlation_id)
        await self._cleanup_stale_jobs(result, correlation_id)

        logger.info(
            "Recovery sweep complete",
            dead_letter_recoveries=result.dead_letter_recoveries,
            orphan_recoveries=result.orphan_recoveries,
            stale_cleanups=result.stale_cleanups,
            skipped=result.skipped,
            errors=result.errors,
            correlation_id=correlation_id,
        )

        return result

    async def _recover_dead_lettered_jobs(
        self, result: RecoveryResult, correlation_id: str
    ) -> None:
        """Find dead-lettered jobs and retry them, up to MAX_AUTO_RECOVERIES times.

        Uses the job's retry_count field: if retry_count > max_retries + MAX_AUTO_RECOVERIES,
        we stop auto-recovering to prevent infinite loops.
        """
        stmt = (
            select(Job)
            .where(Job.stage == "dead_lettered")
            .where(Job.retry_count < Job.max_retries + MAX_AUTO_RECOVERIES)
        )
        jobs_result = await self.session.execute(stmt)
        dead_jobs = jobs_result.scalars().all()

        for job in dead_jobs:
            try:
                # Check if video still needs processing
                video = await self._get_video(job.video_id)
                if not video or video.processing_status == "completed":
                    continue

                # Check if there's already a newer successful job of this type
                has_success = await self._has_succeeded_job(job.video_id, job.job_type)
                if has_success:
                    continue

                # Reset and re-queue
                job.stage = "queued"
                job.status = "pending"
                job.error_message = None
                job.started_at = None
                job.completed_at = None
                job.correlation_id = correlation_id

                self._queue_job(job, video, correlation_id)

                result.dead_letter_recoveries += 1
                result.actions.append(
                    RecoveryAction(
                        action="dead_letter_retry",
                        job_id=job.job_id,
                        video_id=job.video_id,
                        job_type=job.job_type,
                        detail=f"Retried dead-lettered job (attempt {job.retry_count})",
                    )
                )
                logger.info(
                    "Recovered dead-lettered job",
                    job_id=str(job.job_id),
                    job_type=job.job_type,
                    retry_count=job.retry_count,
                )
            except Exception as e:
                result.errors += 1
                logger.error(
                    "Failed to recover dead-lettered job",
                    job_id=str(job.job_id),
                    error=str(e),
                )

        # Also count skipped (exceeded auto-recovery limit)
        skip_stmt = (
            select(func.count())
            .select_from(Job)
            .where(Job.stage == "dead_lettered")
            .where(Job.retry_count >= Job.max_retries + MAX_AUTO_RECOVERIES)
        )
        skip_result = await self.session.execute(skip_stmt)
        result.skipped += skip_result.scalar() or 0

        await self.session.commit()

    async def _recover_orphaned_videos(self, result: RecoveryResult, correlation_id: str) -> None:
        """Find videos stuck in 'processing' with no active/queued jobs.

        These are videos where all jobs completed or failed but the video
        never advanced to the next pipeline stage.
        """
        # Find videos in "processing" status
        processing_videos_stmt = select(Video).where(Video.processing_status == "processing")
        videos_result = await self.session.execute(processing_videos_stmt)
        processing_videos = videos_result.scalars().all()

        for video in processing_videos:
            try:
                # Get all jobs for this video
                jobs_stmt = (
                    select(Job)
                    .where(Job.video_id == video.video_id)
                    .order_by(Job.created_at.desc())
                )
                jobs_result = await self.session.execute(jobs_stmt)
                jobs = jobs_result.scalars().all()

                if not jobs:
                    continue

                # Check if any jobs are still active
                active_stages = {"queued", "running", "rate_limited"}
                active_jobs = [j for j in jobs if j.stage in active_stages]
                if active_jobs:
                    continue  # Video has active jobs, skip

                # Determine which stages have succeeded
                succeeded_types = {j.job_type for j in jobs if j.status == "succeeded"}
                failed_types = {
                    j.job_type for j in jobs if j.status == "failed" or j.stage == "dead_lettered"
                } - succeeded_types

                # If there are failed stages with no success, retry the earliest failed stage
                if failed_types:
                    # Find the earliest failed stage in pipeline order
                    for stage in PIPELINE_STAGES:
                        if stage in failed_types:
                            await self._create_and_queue_job(video, stage, correlation_id, result)
                            break
                    continue

                # All existing jobs succeeded — check if next stage is needed
                next_stage = self._get_next_stage(succeeded_types)
                if next_stage:
                    await self._create_and_queue_job(video, next_stage, correlation_id, result)
                else:
                    # All stages complete, update video status
                    video.processing_status = "completed"
                    result.actions.append(
                        RecoveryAction(
                            action="status_correction",
                            video_id=video.video_id,
                            job_type="all",
                            detail="Corrected video status to completed (all stages done)",
                        )
                    )

            except Exception as e:
                result.errors += 1
                logger.error(
                    "Failed to recover orphaned video",
                    video_id=str(video.video_id),
                    error=str(e),
                )

        await self.session.commit()

    async def _cleanup_stale_jobs(self, result: RecoveryResult, correlation_id: str) -> None:
        """Find jobs stuck in 'running' for too long and mark them failed.

        This handles cases where a worker crashed without updating the job status.
        The dead-letter recovery will pick these up on the next sweep.
        """
        stale_threshold = datetime.utcnow() - timedelta(minutes=STALE_JOB_THRESHOLD_MINUTES)

        stmt = select(Job).where(Job.stage == "running").where(Job.started_at < stale_threshold)
        jobs_result = await self.session.execute(stmt)
        stale_jobs = jobs_result.scalars().all()

        for job in stale_jobs:
            try:
                job.stage = "failed"
                job.status = "failed"
                job.error_message = (
                    f"Auto-recovery: job stale for >{STALE_JOB_THRESHOLD_MINUTES}m "
                    f"(likely worker crash)"
                )
                job.completed_at = datetime.utcnow()

                result.stale_cleanups += 1
                result.actions.append(
                    RecoveryAction(
                        action="stale_cleanup",
                        job_id=job.job_id,
                        video_id=job.video_id,
                        job_type=job.job_type,
                        detail=f"Marked stale job as failed (started {job.started_at})",
                    )
                )
                logger.info(
                    "Cleaned up stale job",
                    job_id=str(job.job_id),
                    started_at=str(job.started_at),
                )
            except Exception as e:
                result.errors += 1
                logger.error(
                    "Failed to cleanup stale job",
                    job_id=str(job.job_id),
                    error=str(e),
                )

        await self.session.commit()

    # --- Helper methods ---

    async def _get_video(self, video_id: UUID) -> Video | None:
        result = await self.session.execute(select(Video).where(Video.video_id == video_id))
        return result.scalar_one_or_none()

    async def _has_succeeded_job(self, video_id: UUID, job_type: str) -> bool:
        """Check if there's already a succeeded job of this type for the video."""
        stmt = (
            select(func.count())
            .select_from(Job)
            .where(
                and_(
                    Job.video_id == video_id,
                    Job.job_type == job_type,
                    Job.status == "succeeded",
                )
            )
        )
        result = await self.session.execute(stmt)
        return (result.scalar() or 0) > 0

    def _get_next_stage(self, succeeded_types: set[str]) -> str | None:
        """Determine the next pipeline stage based on what's succeeded."""
        for stage in PIPELINE_STAGES:
            if stage not in succeeded_types:
                return stage
        return None  # All stages complete

    async def _create_and_queue_job(
        self,
        video: Video,
        job_type: str,
        correlation_id: str,
        result: RecoveryResult,
    ) -> None:
        """Create a new job record and queue it for processing."""
        job = Job(
            video_id=video.video_id,
            job_type=job_type,
            stage="queued",
            status="pending",
            correlation_id=correlation_id,
        )
        self.session.add(job)
        await self.session.flush()  # Get job_id

        self._queue_job(job, video, correlation_id)

        result.orphan_recoveries += 1
        result.actions.append(
            RecoveryAction(
                action="orphan_recovery",
                job_id=job.job_id,
                video_id=video.video_id,
                job_type=job_type,
                detail=f"Created and queued missing {job_type} job",
            )
        )
        logger.info(
            "Recovered orphaned video",
            video_id=str(video.video_id),
            job_type=job_type,
            new_job_id=str(job.job_id),
        )

    def _queue_job(self, job: Job, video: Video, correlation_id: str) -> None:
        """Send a job to the appropriate queue."""
        queue_name = QUEUE_MAP.get(job.job_type, "transcribe-jobs")
        try:
            queue_client = get_queue_client()
            queue_client.send_message(
                queue_name,
                inject_trace_context(
                    {
                        "job_id": str(job.job_id),
                        "video_id": str(job.video_id),
                        "youtube_video_id": getattr(video, "youtube_video_id", ""),
                        "correlation_id": correlation_id,
                        "retry_count": job.retry_count,
                    }
                ),
            )
        except Exception as e:
            logger.error(
                "Failed to queue recovery job",
                job_id=str(job.job_id),
                queue=queue_name,
                error=str(e),
            )
            raise
