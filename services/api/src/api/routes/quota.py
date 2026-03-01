"""Quota status and expedite request API routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
    from shared.db.models import ExpediteRequest, Job, UsageRecord, User
    from shared.logging.config import get_logger
except ImportError:
    import logging

    async def get_session():
        raise NotImplementedError("Database session not available")

    def get_logger(name: str | None = None):
        return logging.getLogger(name)

    ExpediteRequest = None  # type: ignore
    Job = None  # type: ignore
    UsageRecord = None  # type: ignore
    User = None  # type: ignore

from ..dependencies.auth import AuthenticatedUser, require_auth
from ..dependencies.quota import (
    QUOTA_LIMITS,
    get_or_create_user,
    get_usage_count,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/quota", tags=["Quota"])


# --- Response Models ---


class VideoQuotaStatus(BaseModel):
    processed_today: int
    limit: int | None
    remaining: int | None
    queued: int
    estimated_days: int | None


class CopilotQuotaStatus(BaseModel):
    used_this_hour: int
    limit: int | None
    remaining: int | None
    resets_in_seconds: int | None


class ExpediteRequestStatus(BaseModel):
    request_id: UUID | None
    status: str | None  # pending, approved, denied, or None if no active request
    created_at: datetime | None


class QuotaStatusResponse(BaseModel):
    tier: str
    videos: VideoQuotaStatus
    copilot: CopilotQuotaStatus
    expedite: ExpediteRequestStatus | None


class ExpediteRequestCreate(BaseModel):
    reason: str | None = None


class ExpediteRequestResponse(BaseModel):
    request_id: UUID
    status: str
    video_count: int
    message: str


# --- Routes ---


@router.get("", response_model=QuotaStatusResponse, summary="Get Quota Status")
async def get_quota_status(
    user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> QuotaStatusResponse:
    """Get current quota usage and remaining allowances."""
    db_user = await get_or_create_user(session, user)
    tier = db_user.quota_tier
    tier_limits = QUOTA_LIMITS.get(tier)

    # Video quota
    video_limit_config = tier_limits.get("video_submit") if tier_limits else None
    if video_limit_config:
        video_used = await get_usage_count(
            session, db_user.user_id, "video_submit", video_limit_config["window_seconds"]
        )
        video_limit = video_limit_config["max_count"]
        video_remaining = max(0, video_limit - video_used)
    else:
        video_used = 0
        video_limit = None
        video_remaining = None

    # Count queued jobs
    queued_count_result = await session.execute(
        select(func.count(Job.job_id)).where(
            Job.user_id == db_user.user_id,
            Job.quota_status == "quota_queued",
        )
    )
    queued_count = queued_count_result.scalar() or 0
    estimated_days = None
    if queued_count > 0 and video_limit:
        estimated_days = max(1, (queued_count + video_limit - 1) // video_limit)

    # Copilot quota
    copilot_limit_config = tier_limits.get("copilot_query") if tier_limits else None
    if copilot_limit_config:
        copilot_used = await get_usage_count(
            session, db_user.user_id, "copilot_query", copilot_limit_config["window_seconds"]
        )
        copilot_limit = copilot_limit_config["max_count"]
        copilot_remaining = max(0, copilot_limit - copilot_used)
        resets_in = copilot_limit_config["window_seconds"]
    else:
        copilot_used = 0
        copilot_limit = None
        copilot_remaining = None
        resets_in = None

    # Active expedite request
    expedite_result = await session.execute(
        select(ExpediteRequest)
        .where(
            ExpediteRequest.user_id == db_user.user_id,
            ExpediteRequest.status == "pending",
        )
        .order_by(ExpediteRequest.created_at.desc())
        .limit(1)
    )
    active_expedite = expedite_result.scalar_one_or_none()

    return QuotaStatusResponse(
        tier=tier,
        videos=VideoQuotaStatus(
            processed_today=video_used,
            limit=video_limit,
            remaining=video_remaining,
            queued=queued_count,
            estimated_days=estimated_days,
        ),
        copilot=CopilotQuotaStatus(
            used_this_hour=copilot_used,
            limit=copilot_limit,
            remaining=copilot_remaining,
            resets_in_seconds=resets_in,
        ),
        expedite=ExpediteRequestStatus(
            request_id=active_expedite.request_id if active_expedite else None,
            status=active_expedite.status if active_expedite else None,
            created_at=active_expedite.created_at if active_expedite else None,
        )
        if active_expedite
        else None,
    )


@router.post(
    "/expedite",
    response_model=ExpediteRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Request Expedite Processing",
)
async def request_expedite(
    body: ExpediteRequestCreate,
    user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> ExpediteRequestResponse:
    """Request expedited processing of queued videos.

    An admin will review and approve or deny the request.
    """
    db_user = await get_or_create_user(session, user)

    # Check for existing pending request
    existing = await session.execute(
        select(ExpediteRequest).where(
            ExpediteRequest.user_id == db_user.user_id,
            ExpediteRequest.status == "pending",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending expedite request",
        )

    # Count queued videos
    queued_result = await session.execute(
        select(func.count(Job.job_id)).where(
            Job.user_id == db_user.user_id,
            Job.quota_status == "quota_queued",
        )
    )
    queued_count = queued_result.scalar() or 0

    if queued_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No queued videos to expedite",
        )

    expedite = ExpediteRequest(
        user_id=db_user.user_id,
        reason=body.reason,
        video_count=queued_count,
        status="pending",
    )
    session.add(expedite)
    await session.commit()

    logger.info(
        "Expedite request created",
        user_id=str(db_user.user_id),
        video_count=queued_count,
    )

    return ExpediteRequestResponse(
        request_id=expedite.request_id,
        status="pending",
        video_count=queued_count,
        message=f"Expedite request submitted for {queued_count} queued videos. An admin will review your request.",
    )


@router.get(
    "/expedite",
    response_model=ExpediteRequestResponse | None,
    summary="Get Expedite Request Status",
)
async def get_expedite_status(
    user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> ExpediteRequestResponse | None:
    """Get the status of the user's most recent expedite request."""
    db_user = await get_or_create_user(session, user)

    result = await session.execute(
        select(ExpediteRequest)
        .where(ExpediteRequest.user_id == db_user.user_id)
        .order_by(ExpediteRequest.created_at.desc())
        .limit(1)
    )
    expedite = result.scalar_one_or_none()

    if not expedite:
        return None

    return ExpediteRequestResponse(
        request_id=expedite.request_id,
        status=expedite.status,
        video_count=expedite.video_count,
        message=_expedite_status_message(expedite.status, expedite.video_count),
    )


def _expedite_status_message(req_status: str, video_count: int) -> str:
    if req_status == "pending":
        return f"Expedite request pending admin review for {video_count} videos"
    elif req_status == "approved":
        return f"Expedite approved! {video_count} videos are being processed"
    elif req_status == "denied":
        return "Expedite request denied. Videos will continue processing at normal rate"
    return f"Expedite request status: {req_status}"
