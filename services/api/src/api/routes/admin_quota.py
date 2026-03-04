"""Admin quota management routes for expedite request review."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
    from shared.db.models import ExpediteRequest, Job, User
    from shared.logging.config import get_logger
except ImportError:
    import logging

    async def get_session():
        raise NotImplementedError("Database session not available")

    def get_logger(name: str | None = None):
        return logging.getLogger(name)

    ExpediteRequest = None  # type: ignore
    Job = None  # type: ignore
    User = None  # type: ignore

from ..dependencies.auth import AuthenticatedUser, require_auth
from ..dependencies.quota import get_or_create_user

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/admin/expedite-requests", tags=["Admin - Quota"])


# --- Response Models ---


class ExpediteRequestDetail(BaseModel):
    request_id: UUID
    user_id: UUID
    user_email: str | None
    user_name: str | None
    reason: str | None
    video_count: int
    status: str
    created_at: datetime
    reviewed_at: datetime | None


class ExpediteRequestListResponse(BaseModel):
    requests: list[ExpediteRequestDetail]
    total: int


class ExpediteReviewResponse(BaseModel):
    request_id: UUID
    status: str
    jobs_released: int
    message: str


# --- Admin Guard ---


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


# --- Routes ---


@router.get("", response_model=ExpediteRequestListResponse, summary="List Expedite Requests")
async def list_expedite_requests(
    request_status: str | None = Query(None, alias="status", description="Filter by status"),
    admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> ExpediteRequestListResponse:
    """List all expedite requests (admin only)."""
    query = select(ExpediteRequest, User).join(User, ExpediteRequest.user_id == User.user_id)

    if request_status:
        query = query.where(ExpediteRequest.status == request_status)

    query = query.order_by(ExpediteRequest.created_at.desc())
    result = await session.execute(query)
    rows = result.fetchall()

    requests = [
        ExpediteRequestDetail(
            request_id=req.request_id,
            user_id=req.user_id,
            user_email=user.email,
            user_name=user.display_name,
            reason=req.reason,
            video_count=req.video_count,
            status=req.status,
            created_at=req.created_at,
            reviewed_at=req.reviewed_at,
        )
        for req, user in rows
    ]

    return ExpediteRequestListResponse(requests=requests, total=len(requests))


@router.post(
    "/{request_id}/approve",
    response_model=ExpediteReviewResponse,
    summary="Approve Expedite Request",
)
async def approve_expedite(
    request_id: UUID,
    admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> ExpediteReviewResponse:
    """Approve an expedite request and release all queued jobs (admin only)."""
    admin_user = await get_or_create_user(session, admin)

    # Get the request
    result = await session.execute(
        select(ExpediteRequest).where(ExpediteRequest.request_id == request_id)
    )
    expedite = result.scalar_one_or_none()

    if not expedite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")

    if expedite.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request already {expedite.status}",
        )

    # Release all queued jobs for this user
    release_result = await session.execute(
        update(Job)
        .where(
            Job.user_id == expedite.user_id,
            Job.quota_status == "quota_queued",
        )
        .values(quota_status="released")
    )
    jobs_released = release_result.rowcount

    # Update the request
    expedite.status = "approved"
    expedite.reviewed_by = admin_user.user_id
    expedite.reviewed_at = datetime.now(timezone.utc)

    await session.commit()

    logger.info(
        "Expedite request approved",
        request_id=str(request_id),
        user_id=str(expedite.user_id),
        jobs_released=jobs_released,
        admin_id=str(admin_user.user_id),
    )

    # TODO: Dispatch released jobs to Azure Storage Queue
    # This should be handled by the QuotaDispatcher service

    return ExpediteReviewResponse(
        request_id=request_id,
        status="approved",
        jobs_released=jobs_released,
        message=f"Approved! {jobs_released} jobs released for immediate processing.",
    )


@router.post(
    "/{request_id}/deny",
    response_model=ExpediteReviewResponse,
    summary="Deny Expedite Request",
)
async def deny_expedite(
    request_id: UUID,
    admin: AuthenticatedUser = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> ExpediteReviewResponse:
    """Deny an expedite request (admin only)."""
    admin_user = await get_or_create_user(session, admin)

    result = await session.execute(
        select(ExpediteRequest).where(ExpediteRequest.request_id == request_id)
    )
    expedite = result.scalar_one_or_none()

    if not expedite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")

    if expedite.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request already {expedite.status}",
        )

    expedite.status = "denied"
    expedite.reviewed_by = admin_user.user_id
    expedite.reviewed_at = datetime.now(timezone.utc)
    await session.commit()

    logger.info(
        "Expedite request denied",
        request_id=str(request_id),
        user_id=str(expedite.user_id),
        admin_id=str(admin_user.user_id),
    )

    return ExpediteReviewResponse(
        request_id=request_id,
        status="denied",
        jobs_released=0,
        message="Request denied. Videos will continue at normal processing rate.",
    )
