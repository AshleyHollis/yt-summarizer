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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

try:
    from shared.db.models import Artifact, Job, User, Video
    from shared.logging.config import get_logger
    from shared.queue.client import (
        EMBED_QUEUE,
        RELATIONSHIPS_QUEUE,
        SUMMARIZE_QUEUE,
        TRANSCRIBE_QUEUE,
        get_queue_client,
    )
except ImportError:
    import logging

    def get_logger(name: str | None = None):
        return logging.getLogger(name)

    Job = None  # type: ignore
    User = None  # type: ignore
    Artifact = None  # type: ignore
    Video = None  # type: ignore
    TRANSCRIBE_QUEUE = "transcribe-jobs"
    SUMMARIZE_QUEUE = "summarize-jobs"
    EMBED_QUEUE = "embed-jobs"
    RELATIONSHIPS_QUEUE = "relationships-jobs"

    def get_queue_client():
        raise NotImplementedError("Queue client not available")


try:
    from shared.telemetry.context import inject_trace_context
except ImportError:

    def inject_trace_context(payload: dict) -> dict:
        return payload


from ..dependencies.quota import (
    QUOTA_LIMITS,
    get_quota_operation_for_job_type,
    get_usage_count,
    record_usage,
)

logger = get_logger(__name__)

QUEUE_BY_JOB_TYPE = {
    "transcribe": TRANSCRIBE_QUEUE,
    "summarize": SUMMARIZE_QUEUE,
    "embed": EMBED_QUEUE,
    "build_relationships": RELATIONSHIPS_QUEUE,
}

JOB_TYPES_BY_OPERATION = {
    "transcript_extract": ["transcribe"],
    "ai_features": ["summarize", "embed", "build_relationships"],
}


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
            select(Job.user_id).where(Job.quota_status == "quota_queued").group_by(Job.user_id)
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

    async def release_all_for_user(
        self,
        user_id: UUID,
        correlation_id: str,
        result: DispatchResult | None = None,
        defer_if_prerequisites_missing: bool = False,
    ) -> DispatchResult:
        """Release every queued job for a user, typically after an admin approval.

        If prerequisites are not ready and deferred release is enabled, the job is
        marked released but not sent to a worker. This is useful for held AI jobs
        that should be picked up by the transcribe worker once the transcript lands.
        """
        dispatch_result = result or DispatchResult(users_checked=1)
        released = await self._release_all_queued(
            user_id,
            correlation_id,
            dispatch_result,
            defer_if_prerequisites_missing=defer_if_prerequisites_missing,
        )
        if released > 0:
            dispatch_result.actions.append(f"Released {released} jobs for user {user_id}")
        return dispatch_result

    async def _dispatch_for_user(
        self,
        user_id: UUID,
        correlation_id: str,
        result: DispatchResult,
    ) -> int:
        """Dispatch queued jobs for a single user up to their daily quota."""
        # Get user's tier
        user_result = await self.session.execute(select(User).where(User.user_id == user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            return 0

        # Check quota by user-facing operation bucket
        limit_config = QUOTA_LIMITS.get(user.quota_tier, {})
        if limit_config is None:
            # Admin — release all queued jobs
            return await self._release_all_queued(user_id, correlation_id, result)

        released_total = 0
        for operation_type, operation_limit in limit_config.items():
            if operation_type not in JOB_TYPES_BY_OPERATION:
                continue

            max_count = operation_limit["max_count"]
            window_seconds = operation_limit["window_seconds"]
            used = await get_usage_count(self.session, user_id, operation_type, window_seconds)
            remaining = max(0, max_count - used)

            if remaining == 0:
                result.jobs_skipped += 1
                continue

            released_total += await self._release_queued_jobs(
                user_id,
                operation_type,
                remaining,
                correlation_id,
                result,
            )

        return released_total

    async def _release_all_queued(
        self,
        user_id: UUID,
        correlation_id: str,
        result: DispatchResult,
        defer_if_prerequisites_missing: bool = False,
    ) -> int:
        """Release all queued jobs for admin users."""
        jobs_result = await self.session.execute(
            select(Job)
            .where(Job.user_id == user_id, Job.quota_status == "quota_queued")
            .order_by(Job.created_at.asc())
        )
        jobs = list(jobs_result.scalars().all())

        released = 0
        for job in jobs:
            if await self._release_and_dispatch(
                job,
                correlation_id,
                result,
                defer_if_prerequisites_missing=defer_if_prerequisites_missing,
            ):
                result.jobs_released += 1
                released += 1

        return released

    async def _release_queued_jobs(
        self,
        user_id: UUID,
        operation_type: str,
        count: int,
        correlation_id: str,
        result: DispatchResult,
    ) -> int:
        """Release up to `count` queued jobs for a user."""
        job_types = JOB_TYPES_BY_OPERATION.get(operation_type, [])
        if not job_types:
            return 0

        jobs_result = await self.session.execute(
            select(Job)
            .where(
                Job.user_id == user_id,
                Job.quota_status == "quota_queued",
                Job.job_type.in_(job_types),
            )
            .order_by(Job.created_at.asc())
            .limit(count)
        )
        jobs = list(jobs_result.scalars().all())

        released = 0
        for job in jobs:
            if await self._release_and_dispatch(job, correlation_id, result):
                operation = get_quota_operation_for_job_type(job.job_type)
                if operation:
                    await record_usage(
                        self.session,
                        user_id,
                        operation,
                        str(job.video_id),
                    )
                result.jobs_released += 1
                released += 1

        return released

    async def _release_and_dispatch(
        self,
        job: Job,
        correlation_id: str,
        result: DispatchResult,
        defer_if_prerequisites_missing: bool = False,
    ) -> bool:
        """Mark a job as released and dispatch it to the correct worker queue."""
        queue_name = QUEUE_BY_JOB_TYPE.get(job.job_type)
        if not queue_name:
            result.jobs_skipped += 1
            logger.warning("No queue mapping for quota-queued job", job_type=job.job_type)
            return False

        if not await self._prerequisites_met(job):
            if defer_if_prerequisites_missing:
                job.quota_status = "released"
                logger.info(
                    "Released quota-queued job for later dispatch",
                    job_id=str(job.job_id),
                    job_type=job.job_type,
                    video_id=str(job.video_id),
                )
                return True

            result.jobs_skipped += 1
            logger.info(
                "Quota-queued job prerequisites are not ready",
                job_id=str(job.job_id),
                job_type=job.job_type,
                video_id=str(job.video_id),
            )
            return False

        # Get video info for the queue message
        video_result = await self.session.execute(
            select(Video).options(selectinload(Video.channel)).where(Video.video_id == job.video_id)
        )
        video = video_result.scalar_one_or_none()

        if not video:
            logger.warning(
                "Video not found for queued job",
                job_id=str(job.job_id),
                video_id=str(job.video_id),
            )
            return False

        # Dispatch to Azure Storage Queue
        job.quota_status = "released"
        try:
            queue_client = get_queue_client()
            message = inject_trace_context(
                {
                    "job_id": str(job.job_id),
                    "video_id": str(job.video_id),
                    "youtube_video_id": video.youtube_video_id,
                    "channel_name": video.channel.name if video.channel else "unknown-channel",
                    "correlation_id": correlation_id,
                    "processing_mode": job.processing_mode,
                }
            )
            if job.batch_id:
                message["batch_id"] = str(job.batch_id)

            queue_client.send_message(queue_name, message)
            logger.info(
                "Dispatched quota-queued job",
                job_id=str(job.job_id),
                video_id=str(job.video_id),
                queue=queue_name,
            )
            return True
        except Exception as e:
            logger.error(
                "Failed to dispatch job to queue",
                job_id=str(job.job_id),
                error=str(e),
            )
            # Revert quota_status so it can be retried
            job.quota_status = "quota_queued"
            return False

    async def _prerequisites_met(self, job: Job) -> bool:
        """Check whether a quota-queued job can be safely dispatched."""
        if job.job_type != "summarize":
            return True

        transcript_result = await self.session.execute(
            select(Artifact.artifact_id)
            .where(
                Artifact.video_id == job.video_id,
                Artifact.artifact_type == "transcript",
            )
            .limit(1)
        )
        return transcript_result.scalar_one_or_none() is not None
