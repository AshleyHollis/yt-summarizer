"""Admin routes for system management and recovery."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
    from shared.db.models import Job
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")

    Job = None  # type: ignore


from ..dependencies.auth import AuthenticatedUser, require_auth
from ..dependencies.quota import get_or_create_user
from ..services.quota_dispatcher import DispatchResult, QuotaDispatcher
from ..services.recovery_service import RecoveryResult, RecoveryService

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])

BACKUP_JOB_TYPE = "backup_nightly"


async def require_admin(
    user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> AuthenticatedUser:
    """Require the authenticated user to be an admin."""
    db_user = await get_or_create_user(session, user)
    if db_user.quota_tier != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


class BackupChannelProgress(BaseModel):
    slug: str
    name: str | None = None
    status: str
    phase: str | None = None
    total_videos: int = 0
    processed_videos: int = 0
    copied_blobs: int = 0
    skipped_blobs: int = 0
    missing_blobs: int = 0
    bytes_copied: int = 0
    warnings: list[str] = Field(default_factory=list)


class BackupRunSummary(BaseModel):
    job_id: UUID
    run_id: str
    status: str
    stage: str
    progress: int
    started_at: datetime | None
    completed_at: datetime | None
    current_channel: str | None
    total_channels: int
    completed_channels: int
    copied_blobs: int
    skipped_blobs: int
    missing_blobs: int
    bytes_copied: int
    warning_count: int
    warnings: list[str] = Field(default_factory=list)
    report_blob_path: str | None
    error_message: str | None
    channels: list[BackupChannelProgress] = Field(default_factory=list)


class BackupStatusResponse(BaseModel):
    latest_run: BackupRunSummary | None


class BackupRunListResponse(BaseModel):
    runs: list[BackupRunSummary] = Field(default_factory=list)
    total: int


def get_recovery_service(session: AsyncSession = Depends(get_session)) -> RecoveryService:
    """Dependency to get recovery service."""
    return RecoveryService(session)


def _load_backup_metadata(job: Job) -> dict[str, Any]:
    if not getattr(job, "metadata_json", None):
        return {}
    try:
        metadata = json.loads(job.metadata_json)
    except json.JSONDecodeError:
        return {}
    return metadata if isinstance(metadata, dict) else {}


def _backup_run_from_job(job: Job) -> BackupRunSummary:
    metadata = _load_backup_metadata(job)
    warnings = metadata.get("warnings") if isinstance(metadata.get("warnings"), list) else []
    channels = []
    for channel in metadata.get("channels", []):
        if not isinstance(channel, dict):
            continue
        channels.append(
            BackupChannelProgress(
                slug=str(channel.get("slug") or "unknown-channel"),
                name=channel.get("name"),
                status=str(channel.get("status") or "unknown"),
                phase=channel.get("phase"),
                total_videos=int(channel.get("total_videos") or 0),
                processed_videos=int(channel.get("processed_videos") or 0),
                copied_blobs=int(channel.get("copied_blobs") or 0),
                skipped_blobs=int(channel.get("skipped_blobs") or 0),
                missing_blobs=int(channel.get("missing_blobs") or 0),
                bytes_copied=int(channel.get("bytes_copied") or 0),
                warnings=channel.get("warnings")
                if isinstance(channel.get("warnings"), list)
                else [],
            )
        )

    return BackupRunSummary(
        job_id=job.job_id,
        run_id=str(metadata.get("run_id") or job.correlation_id),
        status=job.status,
        stage=job.stage,
        progress=job.progress or 0,
        started_at=job.started_at,
        completed_at=job.completed_at,
        current_channel=metadata.get("current_channel"),
        total_channels=int(metadata.get("total_channels") or len(channels)),
        completed_channels=int(metadata.get("completed_channels") or 0),
        copied_blobs=int(metadata.get("copied_blobs") or 0),
        skipped_blobs=int(metadata.get("skipped_blobs") or 0),
        missing_blobs=int(metadata.get("missing_blobs") or 0),
        bytes_copied=int(metadata.get("bytes_copied") or 0),
        warning_count=len(warnings),
        warnings=[str(warning) for warning in warnings],
        report_blob_path=metadata.get("report_blob_path"),
        error_message=job.error_message,
        channels=channels,
    )


async def _latest_backup_job(session: AsyncSession) -> Job | None:
    result = await session.execute(
        select(Job)
        .where(Job.video_id.is_(None), Job.job_type == BACKUP_JOB_TYPE)
        .order_by(Job.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


@router.get(
    "/backups/status",
    response_model=BackupStatusResponse,
    summary="Backup Status",
    description="Get the latest nightly backup status from the system job row.",
)
async def get_backup_status(
    _admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> BackupStatusResponse:
    """Get the latest backup run status."""
    job = await _latest_backup_job(session)
    return BackupStatusResponse(latest_run=_backup_run_from_job(job) if job else None)


@router.get(
    "/backups/runs",
    response_model=BackupRunListResponse,
    summary="Backup Runs",
    description="List recent nightly backup runs.",
)
async def list_backup_runs(
    limit: int = Query(default=30, ge=1, le=100),
    _admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> BackupRunListResponse:
    """List recent backup runs."""
    query = (
        select(Job)
        .where(Job.video_id.is_(None), Job.job_type == BACKUP_JOB_TYPE)
        .order_by(Job.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(query)
    jobs = result.scalars().all()
    runs = [_backup_run_from_job(job) for job in jobs]
    return BackupRunListResponse(runs=runs, total=len(runs))


@router.get(
    "/backups/runs/{job_id}",
    response_model=BackupRunSummary,
    summary="Backup Run Detail",
    description="Get one nightly backup run by system job ID.",
)
async def get_backup_run(
    job_id: UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> BackupRunSummary:
    """Get backup run detail."""
    result = await session.execute(
        select(Job).where(
            Job.job_id == job_id,
            Job.video_id.is_(None),
            Job.job_type == BACKUP_JOB_TYPE,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup run not found",
        )
    return _backup_run_from_job(job)


@router.post(
    "/recovery/run",
    response_model=RecoveryResult,
    summary="Run Recovery Sweep",
    description=(
        "Automatically recover stuck/failed video processing jobs. "
        "Retries dead-lettered jobs, re-queues orphaned videos, "
        "and cleans up stale running jobs."
    ),
)
async def run_recovery_sweep(
    request: Request,
    _user: AuthenticatedUser = Depends(require_auth),
    service: RecoveryService = Depends(get_recovery_service),
) -> RecoveryResult:
    """Run a complete recovery sweep."""
    correlation_id = getattr(request.state, "correlation_id", "recovery-manual")
    return await service.run_recovery_sweep(correlation_id)


@router.get(
    "/recovery/status",
    summary="Recovery Status",
    description="Check for stuck/failed jobs without taking action.",
)
async def recovery_status(
    _user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Check current system health without taking recovery actions."""
    from sqlalchemy import func, select

    try:
        from shared.db.models import Job, Video
    except ImportError:
        return {"error": "shared module not available"}

    # Count dead-lettered jobs
    dead_result = await session.execute(
        select(func.count())
        .select_from(Job)
        .where(Job.stage == "dead_lettered")
        .where(Job.video_id.is_not(None))
    )
    dead_count = dead_result.scalar() or 0

    # Count stale running jobs (>15 min)
    from datetime import datetime, timedelta

    stale_threshold = datetime.utcnow() - timedelta(minutes=15)
    stale_result = await session.execute(
        select(func.count())
        .select_from(Job)
        .where(Job.stage == "running")
        .where(Job.video_id.is_not(None))
        .where(Job.started_at < stale_threshold)
    )
    stale_count = stale_result.scalar() or 0

    # Count processing videos with no active jobs
    processing_result = await session.execute(
        select(func.count()).select_from(Video).where(Video.processing_status == "processing")
    )
    processing_count = processing_result.scalar() or 0

    # Count active jobs
    active_result = await session.execute(
        select(func.count())
        .select_from(Job)
        .where(Job.video_id.is_not(None))
        .where(Job.stage.in_(["queued", "running", "rate_limited"]))
    )
    active_count = active_result.scalar() or 0

    return {
        "dead_lettered_jobs": dead_count,
        "stale_running_jobs": stale_count,
        "processing_videos": processing_count,
        "active_jobs": active_count,
        "needs_recovery": dead_count > 0 or stale_count > 0,
    }


def get_quota_dispatcher(session: AsyncSession = Depends(get_session)) -> QuotaDispatcher:
    """Dependency to get quota dispatcher service."""
    return QuotaDispatcher(session)


@router.post(
    "/quota/dispatch",
    response_model=DispatchResult,
    summary="Run Quota Dispatch Sweep",
    description=(
        "Release quota-queued jobs for users who have available daily quota. "
        "Intended to be called by a cron job or manually by admins."
    ),
)
async def run_quota_dispatch(
    request: Request,
    _user: AuthenticatedUser = Depends(require_auth),
    dispatcher: QuotaDispatcher = Depends(get_quota_dispatcher),
) -> DispatchResult:
    """Run a quota dispatch sweep to release queued jobs."""
    correlation_id = getattr(request.state, "correlation_id", "quota-dispatch-manual")
    return await dispatcher.run_dispatch_sweep(correlation_id)


class DeleteVideosByUrlsRequest(BaseModel):
    urls: list[str]


@router.delete(
    "/videos/by-urls",
    status_code=status.HTTP_200_OK,
    summary="Delete Videos by URLs",
    description=(
        "Delete videos (and their associated jobs/segments) by YouTube URL. "
        "Used by CI/E2E test seeding to clear stale data before re-runs."
    ),
)
async def delete_videos_by_urls(
    body: DeleteVideosByUrlsRequest,
    _user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Delete videos matching the given YouTube URLs."""
    from sqlalchemy import delete as sql_delete

    try:
        from shared.db.models import Job, Video
    except ImportError:
        return {"error": "shared module not available", "deleted": 0}

    from ..models.video import extract_youtube_video_id

    # Resolve YouTube video IDs from URLs
    youtube_ids = [extract_youtube_video_id(u) for u in body.urls]
    youtube_ids = [yid for yid in youtube_ids if yid]

    if not youtube_ids:
        return {"deleted": 0, "skipped": len(body.urls)}

    # Fetch matching videos
    from sqlalchemy import select

    result = await session.execute(select(Video).where(Video.youtube_video_id.in_(youtube_ids)))
    videos = result.scalars().all()

    deleted = 0
    for video in videos:
        await session.execute(sql_delete(Job).where(Job.video_id == video.video_id))
        await session.execute(sql_delete(Video).where(Video.video_id == video.video_id))
        deleted += 1

    await session.commit()
    return {"deleted": deleted, "skipped": len(body.urls) - deleted}
