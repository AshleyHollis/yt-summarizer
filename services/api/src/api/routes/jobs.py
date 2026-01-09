"""Job API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.connection import get_session
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")


from ..middleware.correlation import get_correlation_id
from ..models.job import (
    JobListFilters,
    JobListResponse,
    JobResponse,
    JobStage,
    JobStatus,
    JobType,
    RetryJobRequest,
    RetryJobResponse,
    VideoJobsProgress,
    VideoProcessingHistory,
)
from ..services.job_service import JobService

router = APIRouter(prefix="/api/v1/jobs", tags=["Jobs"])


def get_job_service(session: AsyncSession = Depends(get_session)) -> JobService:
    """Dependency to get job service."""
    return JobService(session)


@router.get(
    "",
    response_model=JobListResponse,
    summary="List Jobs",
    description="List jobs with optional filters",
)
async def list_jobs(
    video_id: UUID | None = Query(default=None, description="Filter by video ID"),
    batch_id: UUID | None = Query(default=None, description="Filter by batch ID"),
    job_type: JobType | None = Query(default=None, description="Filter by job type"),
    job_status: JobStatus | None = Query(
        default=None, alias="status", description="Filter by status"
    ),
    stage: JobStage | None = Query(default=None, description="Filter by stage"),
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    service: JobService = Depends(get_job_service),
) -> JobListResponse:
    """List jobs with optional filters.

    Supports filtering by video ID, batch ID, job type, status, and stage.
    Results are paginated.
    """
    filters = JobListFilters(
        video_id=video_id,
        batch_id=batch_id,
        job_type=job_type,
        status=job_status,
        stage=stage,
    )

    return await service.list_jobs(filters, page, per_page)


@router.get(
    "/{job_id}",
    response_model=JobResponse,
    summary="Get Job",
    description="Get job details by ID",
)
async def get_job(
    job_id: UUID,
    service: JobService = Depends(get_job_service),
) -> JobResponse:
    """Get a job by ID.

    Returns full job details including status, progress,
    error message, and timing information.
    """
    result = await service.get_job(job_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found",
        )

    return result


@router.post(
    "/{job_id}/retry",
    response_model=RetryJobResponse,
    summary="Retry Job",
    description="Retry a failed job",
)
async def retry_job(
    request: Request,
    job_id: UUID,
    body: RetryJobRequest | None = None,
    service: JobService = Depends(get_job_service),
) -> RetryJobResponse:
    """Retry a failed job.

    Re-queues the job for processing. Optionally resets the retry count.
    Only failed or dead-lettered jobs can be retried.
    """
    correlation_id = get_correlation_id(request)
    reset_retries = body.reset_retries if body else False

    result = await service.retry_job(job_id, reset_retries, correlation_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found",
        )

    return result


@router.get(
    "/video/{video_id}/progress",
    response_model=VideoJobsProgress,
    summary="Get Video Progress",
    description="Get progress of all jobs for a video",
)
async def get_video_progress(
    video_id: UUID,
    service: JobService = Depends(get_job_service),
) -> VideoJobsProgress:
    """Get progress of all jobs for a video.

    Returns overall progress percentage and status of each
    processing stage (transcribe, summarize, embed, relationships).
    """
    result = await service.get_video_jobs_progress(video_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    return result


@router.get(
    "/video/{video_id}/history",
    response_model=VideoProcessingHistory,
    summary="Get Video Processing History",
    description="Get detailed processing history with actual vs estimated times",
)
async def get_video_history(
    video_id: UUID,
    service: JobService = Depends(get_job_service),
) -> VideoProcessingHistory:
    """Get detailed processing history for a video.

    Returns actual vs estimated times for each stage, variance analysis,
    and comparison to average processing times. Useful for:
    - Seeing how long each processing step took
    - Comparing actual vs estimated times
    - Identifying slow stages for debugging
    - Understanding retry history
    """
    result = await service.get_video_processing_history(video_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    return result
