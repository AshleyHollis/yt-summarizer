"""Admin routes for system management and recovery."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")


from ..services.quota_dispatcher import DispatchResult, QuotaDispatcher
from ..services.recovery_service import RecoveryResult, RecoveryService

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


def get_recovery_service(session: AsyncSession = Depends(get_session)) -> RecoveryService:
    """Dependency to get recovery service."""
    return RecoveryService(session)


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
        select(func.count()).select_from(Job).where(Job.stage == "dead_lettered")
    )
    dead_count = dead_result.scalar() or 0

    # Count stale running jobs (>15 min)
    from datetime import datetime, timedelta

    stale_threshold = datetime.utcnow() - timedelta(minutes=15)
    stale_result = await session.execute(
        select(func.count())
        .select_from(Job)
        .where(Job.stage == "running")
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
    dispatcher: QuotaDispatcher = Depends(get_quota_dispatcher),
) -> DispatchResult:
    """Run a quota dispatch sweep to release queued jobs."""
    correlation_id = getattr(request.state, "correlation_id", "quota-dispatch-manual")
    return await dispatcher.run_dispatch_sweep(correlation_id)
