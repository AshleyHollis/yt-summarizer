"""Quota configuration and enforcement dependencies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
    from shared.db.models import UsageRecord, User
    from shared.logging.config import get_logger
except ImportError:
    import logging

    async def get_session():
        raise NotImplementedError("Database session not available")

    def get_logger(name: str | None = None):
        return logging.getLogger(name)

    UsageRecord = None  # type: ignore
    User = None  # type: ignore

from .auth import AuthenticatedUser, require_auth

logger = get_logger(__name__)


# Quota limits defined in code for simplicity.
# To add tiers (e.g., "pro"), add another entry with different limits.
QUOTA_LIMITS: dict[str, dict[str, Any] | None] = {
    "free": {
        "video_submit": {"max_count": 5, "window_seconds": 86400},  # 5 per day
        "copilot_query": {"max_count": 30, "window_seconds": 3600},  # 30 per hour
    },
    "admin": None,  # No limits — bypass all checks
}


async def get_or_create_user(
    session: AsyncSession,
    auth_user: AuthenticatedUser,
) -> User:
    """Find existing user by Auth0 ID or create a new one."""
    result = await session.execute(
        select(User).where(User.auth0_id == auth_user.sub)
    )
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            auth0_id=auth_user.sub,
            email=auth_user.email,
            display_name=auth_user.name,
            quota_tier="free",
        )
        session.add(user)
        await session.flush()
        logger.info("Created new user", auth0_id=auth_user.sub, email=auth_user.email)

    return user


async def get_usage_count(
    session: AsyncSession,
    user_id: Any,
    operation_type: str,
    window_seconds: int,
) -> int:
    """Count usage records for a user within a time window."""
    window_start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    result = await session.execute(
        select(func.count(UsageRecord.usage_id)).where(
            UsageRecord.user_id == user_id,
            UsageRecord.operation_type == operation_type,
            UsageRecord.created_at >= window_start,
        )
    )
    return result.scalar() or 0


async def record_usage(
    session: AsyncSession,
    user_id: Any,
    operation_type: str,
    resource_id: str | None = None,
) -> None:
    """Record a usage event."""
    record = UsageRecord(
        user_id=user_id,
        operation_type=operation_type,
        resource_id=resource_id,
    )
    session.add(record)
    await session.flush()


def get_quota_limit(tier: str, operation_type: str) -> dict[str, int] | None:
    """Get the quota limit for a tier and operation type.

    Returns None if the tier has no limits (e.g., admin).
    """
    tier_limits = QUOTA_LIMITS.get(tier)
    if tier_limits is None:
        return None
    return tier_limits.get(operation_type)


async def check_copilot_quota(
    request: Request,
    user: AuthenticatedUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
) -> AuthenticatedUser:
    """FastAPI dependency that enforces copilot query quota.

    Returns the authenticated user if under quota.
    Raises 429 if over quota.
    Admin users bypass quota checks.
    """
    db_user = await get_or_create_user(session, user)
    limit = get_quota_limit(db_user.quota_tier, "copilot_query")

    if limit is None:
        # Admin — no limits
        return user

    current_count = await get_usage_count(
        session, db_user.user_id, "copilot_query", limit["window_seconds"]
    )

    if current_count >= limit["max_count"]:
        retry_after = limit["window_seconds"]
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Copilot query quota exceeded",
                "used": current_count,
                "limit": limit["max_count"],
                "window_seconds": limit["window_seconds"],
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    # Record the usage
    await record_usage(session, db_user.user_id, "copilot_query")
    await session.commit()

    return user


async def check_video_quota(
    session: AsyncSession,
    db_user: User,
) -> dict[str, Any]:
    """Check video submission quota for a user.

    Returns quota status dict:
    {
        "tier": str,
        "remaining": int | None (None = unlimited),
        "used_today": int,
        "limit": int | None,
    }
    """
    limit = get_quota_limit(db_user.quota_tier, "video_submit")

    if limit is None:
        return {
            "tier": db_user.quota_tier,
            "remaining": None,
            "used_today": 0,
            "limit": None,
        }

    used_today = await get_usage_count(
        session, db_user.user_id, "video_submit", limit["window_seconds"]
    )
    remaining = max(0, limit["max_count"] - used_today)

    return {
        "tier": db_user.quota_tier,
        "remaining": remaining,
        "used_today": used_today,
        "limit": limit["max_count"],
    }
