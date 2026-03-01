"""Quota Dispatcher service for releasing queued jobs at the quota rate.

This service ensures that users' queued videos are dispatched to the
Azure Storage Queue at their daily quota rate (e.g., 5/day for free tier).

Triggered by:
1. Periodic cron (via admin endpoint, similar to RecoveryService)
2. Could also be called on video completion to chain the next video
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.models import Job, UsageRecord, User, Video
    from shared.logging.config import get_logger
    from shared.queue.client import TRANSCRIBE_QUEUE, get_queue_client
except ImportError:
    import logging

    def get_logger(name: str | None = None):
        return logging.getLogger(name)

    Job = None  # type: ignore
    User = None  # type: ignore
    UsageRecord = None  # type: ignore
    Video = None  # type: ignore
    TRANSCRIBE_QUEUE = "transcribe-jobs"

    def get_queue_client():
        raise NotImplementedError("Queue client not available")


try:
    from shared.telemetry.context import inject_trace_context
except ImportError:

    def inject_trace_context(payload: dict) -> dict:
        return payload


from ..dependencies.quota import QUOTA_LIMITS, get_usage_count

logger = get_logger(__name__)


@dataclass
class DispatchResult:
    """Result of a quota dispatch sweep."""

    users_checked: int = 0
    jobs_released: int = 0
    jobs_skipped: int = 0
    actions: list[str] = field(default_factory=list)


class QuotaDispatcher:
    """Dispatches quota-queued jobs to worker queues at the user's quota rate."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def run_dispatch_sweep(self, correlation_id: str) -> DispatchResult:
        """Check all users with queued jobs and dispatch within their quota."""
        result = DispatchResult()

        # Find all users with quota_queued jobs
        users_with_queued = await self.session.execute(
            select(Job.user_id)
            .where(Job.quota_status == "quota_queued")
            .group_by(Job.user_id)
        )
        user_ids = [row[0] for row in users_with_queued.fetchall() if row[0] is not None]

        for user_id in user_ids:
            result.users_checked += 1
            released = await self._dispatch_for_user(user_id, correlation_id, result)
            if released > 0:
                result.actions.append(f"Released {released} jobs for user {user_id}")

        if result.jobs_released > 0:
            await self.session.commit()

        logger.info(
            "Quota dispatch sweep completed",
            users_checked=result.users_checked,
            jobs_released=result.jobs_released,
            correlation_id=correlation_id,
        )

        return result

    async def _dispatch_for_user(
        self,
        user_id: UUID,
        correlation_id: str,
        result: DispatchResult,
    ) -> int:
        """Dispatch queued jobs for a single user up to their daily quota."""
        # Get user's tier
        user_result = await self.session.execute(
            select(User).where(User.user_id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return 0

        # Check quota
        limit_config = QUOTA_LIMITS.get(user.quota_tier, {})
        if limit_config is None:
            # Admin — release all queued jobs
            return await self._release_all_queued(user_id, correlation_id, result)

        video_limit = limit_config.get("video_submit", {})
        if not video_limit:
            return 0

        max_count = video_limit["max_count"]
        window_seconds = video_limit["window_seconds"]

        # Count how many videos processed today
        used_today = await get_usage_count(
            self.session, user_id, "video_submit", window_seconds
        )
        remaining = max(0, max_count - used_today)

        if remaining == 0:
            result.jobs_skipped += 1
            return 0

        return await self._release_queued_jobs(
            user_id, remaining, correlation_id, result
        )

    async def _release_all_queued(
        self,
        user_id: UUID,
        correlation_id: str,
        result: DispatchResult,
    ) -> int:
        """Release all queued jobs for admin users."""
        jobs_result = await self.session.execute(
            select(Job)
            .where(Job.user_id == user_id, Job.quota_status == "quota_queued")
            .order_by(Job.created_at.asc())
        )
        jobs = list(jobs_result.scalars().all())

        for job in jobs:
            await self._release_and_dispatch(job, correlation_id)
            result.jobs_released += 1

        return len(jobs)

    async def _release_queued_jobs(
        self,
        user_id: UUID,
        count: int,
        correlation_id: str,
        result: DispatchResult,
    ) -> int:
        """Release up to `count` queued jobs for a user."""
        jobs_result = await self.session.execute(
            select(Job)
            .where(Job.user_id == user_id, Job.quota_status == "quota_queued")
            .order_by(Job.created_at.asc())
            .limit(count)
        )
        jobs = list(jobs_result.scalars().all())

        released = 0
        for job in jobs:
            await self._release_and_dispatch(job, correlation_id)
            result.jobs_released += 1
            released += 1

        return released

    async def _release_and_dispatch(self, job: Job, correlation_id: str) -> None:
        """Mark a job as released and dispatch it to the worker queue."""
        job.quota_status = "released"

        # Get video info for the queue message
        video_result = await self.session.execute(
            select(Video).where(Video.video_id == job.video_id)
        )
        video = video_result.scalar_one_or_none()

        if not video:
            logger.warning(
                "Video not found for queued job",
                job_id=str(job.job_id),
                video_id=str(job.video_id),
            )
            return

        # Dispatch to Azure Storage Queue
        try:
            queue_client = get_queue_client()
            queue_client.send_message(
                TRANSCRIBE_QUEUE,
                inject_trace_context(
                    {
                        "job_id": str(job.job_id),
                        "video_id": str(job.video_id),
                        "youtube_video_id": video.youtube_video_id,
                        "channel_name": getattr(video, "channel", None)
                        and video.channel.name
                        or "unknown",
                        "correlation_id": correlation_id,
                    }
                ),
            )
            logger.info(
                "Dispatched quota-queued job",
                job_id=str(job.job_id),
                video_id=str(job.video_id),
            )
        except Exception as e:
            logger.error(
                "Failed to dispatch job to queue",
                job_id=str(job.job_id),
                error=str(e),
            )
            # Revert quota_status so it can be retried
            job.quota_status = "quota_queued"
