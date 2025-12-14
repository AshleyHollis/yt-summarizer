"""Job status update utilities."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select

from shared.db.connection import get_db
from shared.db.models import Job
from shared.logging.config import get_logger

logger = get_logger(__name__)


async def update_job_status(
    job_id: str,
    status: str,
    stage: Optional[str] = None,
    error_message: Optional[str] = None,
    progress: Optional[int] = None,
) -> None:
    """Update job status in the database.

    Args:
        job_id: The job ID to update.
        status: New status value (pending, running, completed, failed).
        stage: New stage value (queued, transcribing, summarizing, etc.).
        error_message: Error message if failed.
        progress: Progress percentage (0-100).
    """
    db = get_db()
    async with db.session() as session:
        result = await session.execute(
            select(Job).where(Job.job_id == UUID(job_id))
        )
        job = result.scalar_one_or_none()

        if not job:
            logger.warning("Job not found for status update", job_id=job_id)
            return

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

        logger.info(
            "Updated job status",
            job_id=job_id,
            status=status,
            stage=stage,
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
    """Mark a job as completed.

    Args:
        job_id: The job ID to update.
    """
    await update_job_status(job_id, status="succeeded", stage="completed", progress=100)


async def mark_job_failed(job_id: str, error_message: str) -> None:
    """Mark a job as failed with an error message.

    Args:
        job_id: The job ID to update.
        error_message: Description of the error.
    """
    await update_job_status(job_id, status="failed", stage="failed", error_message=error_message)
