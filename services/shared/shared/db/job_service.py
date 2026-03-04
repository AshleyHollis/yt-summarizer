"""Job status update utilities."""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from shared.db.connection import get_db
from shared.db.models import Batch, BatchItem, Job, JobHistory, Video
from shared.logging.config import get_logger

logger = get_logger(__name__)


async def update_job_status(
    job_id: str,
    status: str,
    stage: str | None = None,
    error_message: str | None = None,
    progress: int | None = None,
) -> None:
    """Update job status in the database.

    Also updates the associated BatchItem and Batch counts when:
    - Job starts running (batch item goes to "running")
    - Final job (build_relationships) completes (batch item goes to "succeeded")
    - Any job fails (batch item goes to "failed")

    Args:
        job_id: The job ID to update.
        status: New status value (pending, running, succeeded, failed).
        stage: New stage value (queued, running, completed, failed, dead_lettered).
        error_message: Error message if failed.
        progress: Progress percentage (0-100).
    """
    db = get_db()
    async with db.session() as session:
        result = await session.execute(select(Job).where(Job.job_id == UUID(job_id)))
        job = result.scalar_one_or_none()

        if not job:
            logger.warning("Job not found for status update", job_id=job_id)
            return

        old_status = job.status
        job_type = job.job_type

        # Update status
        job.status = status

        # Update stage if provided
        if stage is not None:
            job.stage = stage

        # Update error message if provided
        if error_message is not None:
            job.error_message = error_message

        # Update progress if provided
        if progress is not None:
            job.progress = progress

        # Set timestamps based on status
        if status == "running" and job.started_at is None:
            job.started_at = datetime.utcnow()
        elif status in ("succeeded", "failed"):
            job.completed_at = datetime.utcnow()

        # Always sync video.processing_status based on job transitions
        if old_status != status:
            video_status = None
            if status == "running" and old_status == "pending":
                video_status = "processing"
            elif status == "failed":
                video_status = "failed"
            elif status == "succeeded" and job_type == "build_relationships":
                video_status = "completed"

            if video_status:
                video_result = await session.execute(
                    select(Video).where(Video.video_id == job.video_id)
                )
                video = video_result.scalar_one_or_none()
                if video:
                    video.processing_status = video_status
                    if status == "failed" and error_message:
                        video.error_message = error_message

        # Update batch item and batch counts if this is a batch job
        if job.batch_id and old_status != status:
            # Determine the batch item status based on job type and new status
            # - "running": when first job starts running
            # - "succeeded": only when final job (build_relationships) succeeds
            # - "failed": when any job fails
            batch_item_status = None

            if status == "running" and old_status == "pending":
                # First job starting - mark as running
                batch_item_status = "running"
            elif status == "failed":
                # Any job failure - mark as failed
                batch_item_status = "failed"
            elif status == "succeeded" and job_type == "build_relationships":
                # Final job succeeded - mark as succeeded
                batch_item_status = "succeeded"
            # For intermediate job successes (transcribe, summarize, embed),
            # don't update batch item status - it stays "running"

            if batch_item_status:
                await _update_batch_item_status(
                    session, job.batch_id, job.video_id, batch_item_status, error_message
                )

        await session.commit()

        logger.info(
            "Updated job status",
            job_id=job_id,
            status=status,
            stage=stage,
            job_type=job_type,
            batch_id=str(job.batch_id) if job.batch_id else None,
        )


async def _update_batch_item_status(
    session,
    batch_id: UUID,
    video_id: UUID,
    new_status: str,
    error_message: str | None = None,
) -> None:
    """Update batch item status and batch counts.

    Args:
        session: Database session.
        batch_id: Batch ID.
        video_id: Video ID.
        new_status: New status (running, succeeded, failed).
        error_message: Error message for failed status.
    """
    # Get the batch item for this video in this batch
    result = await session.execute(
        select(BatchItem).where(
            BatchItem.batch_id == batch_id,
            BatchItem.video_id == video_id,
        )
    )
    batch_item = result.scalar_one_or_none()

    if not batch_item:
        logger.warning(
            "BatchItem not found for status update",
            batch_id=str(batch_id),
            video_id=str(video_id),
        )
        return

    old_item_status = batch_item.status

    # Map job status to batch item status
    item_status_map = {
        "pending": "pending",
        "running": "running",
        "succeeded": "succeeded",
        "failed": "failed",
    }
    new_item_status = item_status_map.get(new_status, new_status)

    # Only update if status actually changed
    if old_item_status == new_item_status:
        return

    batch_item.status = new_item_status

    # Also update video error message if failed
    if new_status == "failed" and error_message:
        video_result = await session.execute(select(Video).where(Video.video_id == video_id))
        video = video_result.scalar_one_or_none()
        if video:
            video.error_message = error_message
            video.processing_status = "failed"
    elif new_status == "succeeded":
        video_result = await session.execute(select(Video).where(Video.video_id == video_id))
        video = video_result.scalar_one_or_none()
        if video:
            video.processing_status = "completed"

    # Update batch counts
    batch_result = await session.execute(select(Batch).where(Batch.batch_id == batch_id))
    batch = batch_result.scalar_one_or_none()

    if not batch:
        logger.warning(
            "Batch not found for count update",
            batch_id=str(batch_id),
        )
        return

    # Decrement old status count
    if old_item_status == "pending":
        batch.pending_count = max(0, batch.pending_count - 1)
    elif old_item_status == "running":
        batch.running_count = max(0, batch.running_count - 1)
    elif old_item_status == "succeeded":
        batch.succeeded_count = max(0, batch.succeeded_count - 1)
    elif old_item_status == "failed":
        batch.failed_count = max(0, batch.failed_count - 1)

    # Increment new status count
    if new_item_status == "pending":
        batch.pending_count += 1
    elif new_item_status == "running":
        batch.running_count += 1
    elif new_item_status == "succeeded":
        batch.succeeded_count += 1
    elif new_item_status == "failed":
        batch.failed_count += 1

    # Check if batch is complete
    if batch.pending_count == 0 and batch.running_count == 0:
        batch.completed_at = datetime.utcnow()

    logger.info(
        "Updated batch item status",
        batch_id=str(batch_id),
        video_id=str(video_id),
        old_status=old_item_status,
        new_status=new_item_status,
        batch_counts={
            "pending": batch.pending_count,
            "running": batch.running_count,
            "succeeded": batch.succeeded_count,
            "failed": batch.failed_count,
        },
    )


async def mark_job_running(job_id: str, stage: str = "running") -> None:
    """Mark a job as running.

    Args:
        job_id: The job ID to update.
        stage: The stage name. Defaults to 'running'.
               Note: Only 'queued', 'running', 'completed', 'failed', 'dead_lettered' are valid.
    """
    await update_job_status(job_id, status="running", stage="running")


async def mark_job_completed(job_id: str) -> None:
    """Mark a job as completed and record in job history.

    Args:
        job_id: The job ID to update.
    """
    await update_job_status(
        job_id, status="succeeded", stage="completed", progress=100, error_message=""
    )

    # Record in job history for ETA calculations
    await _record_job_history(job_id, success=True)


async def mark_job_failed(job_id: str, error_message: str) -> None:
    """Mark a job as failed with an error message.

    Args:
        job_id: The job ID to update.
        error_message: Description of the error.
    """
    await update_job_status(job_id, status="failed", stage="failed", error_message=error_message)


async def mark_job_rate_limited(job_id: str, video_id: str, retry_delay_seconds: int) -> None:
    """Mark a job as rate limited.

    Updates the job stage to 'rate_limited' and also updates the
    video's processing_status so the UI can display the rate limit state.

    Args:
        job_id: The job ID to update.
        video_id: The video ID to update processing_status.
        retry_delay_seconds: Seconds until the next retry (default 5 minutes).
    """
    # Calculate next retry time
    next_retry_at = datetime.utcnow() + timedelta(seconds=retry_delay_seconds)

    # Update job stage and next_retry_at
    db = get_db()
    async with db.session() as session:
        result = await session.execute(select(Job).where(Job.job_id == UUID(job_id)))
        job = result.scalar_one_or_none()
        if job:
            job.stage = "rate_limited"
            job.status = "running"
            job.next_retry_at = next_retry_at
            job.retry_count = job.retry_count + 1  # Increment to track attempts
            await session.commit()
            logger.info(
                "Marked job as rate limited",
                job_id=job_id,
                next_retry_at=next_retry_at.isoformat(),
                retry_count=job.retry_count,
            )
        else:
            logger.warning("Job not found for rate limited update", job_id=job_id)

    # Also update video processing_status directly so UI shows it
    async with db.session() as session:
        result = await session.execute(select(Video).where(Video.video_id == UUID(video_id)))
        video = result.scalar_one_or_none()
        if video:
            video.processing_status = "rate_limited"
            await session.commit()
            logger.info(
                "Updated video processing_status to rate_limited",
                video_id=video_id,
            )


async def _record_job_history(job_id: str, success: bool) -> None:
    """Record a job completion in the JobHistory table for ETA calculations.

    Args:
        job_id: The job ID that completed.
        success: Whether the job succeeded.
    """
    db = get_db()
    async with db.session() as session:
        # Get the job details
        result = await session.execute(select(Job).where(Job.job_id == UUID(job_id)))
        job = result.scalar_one_or_none()

        if not job:
            logger.warning("Job not found for history recording", job_id=job_id)
            return

        if not job.started_at or not job.completed_at:
            logger.warning(
                "Job missing timestamps for history recording",
                job_id=job_id,
                started_at=job.started_at,
                completed_at=job.completed_at,
            )
            return

        # Get the video duration if available
        video_result = await session.execute(select(Video).where(Video.video_id == job.video_id))
        video = video_result.scalar_one_or_none()
        video_duration = video.duration if video else None

        # Calculate processing duration
        processing_duration = (job.completed_at - job.started_at).total_seconds()

        # Calculate wait time (time from creation to start)
        wait_seconds = None
        if job.created_at and job.started_at:
            wait_seconds = (job.started_at - job.created_at).total_seconds()

        # Create history record with estimated and actual wait times
        history = JobHistory(
            job_id=job.job_id,
            video_id=job.video_id,
            job_type=job.job_type,
            video_duration_seconds=video_duration,
            queued_at=job.created_at,
            wait_seconds=wait_seconds,
            estimated_wait_seconds=job.estimated_wait_seconds,
            processing_duration_seconds=processing_duration,
            started_at=job.started_at,
            completed_at=job.completed_at,
            success=success,
            retry_count=job.retry_count,
        )
        session.add(history)
        await session.commit()

        logger.info(
            "Recorded job history",
            job_id=job_id,
            job_type=job.job_type,
            processing_duration_seconds=processing_duration,
            wait_seconds=wait_seconds,
            estimated_wait_seconds=job.estimated_wait_seconds,
            success=success,
        )
