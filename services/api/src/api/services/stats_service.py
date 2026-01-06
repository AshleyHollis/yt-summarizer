"""Stats service for ETA calculations and processing analytics."""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.models import Job, JobHistory, Video
    from shared.logging.config import get_logger
except ImportError:
    from typing import Any

    Job = Any
    JobHistory = Any
    Video = Any

    def get_logger(name):
        import logging
        return logging.getLogger(name)


logger = get_logger(__name__)

# Default average processing times (seconds) when no history available
# These are based on observed real-world performance (Jan 2026 data)
# Note: Transcribe includes the enforced delay since that's what users experience
DEFAULT_PROCESSING_TIMES = {
    "transcribe": 70.0,  # ~65s enforced delay + ~5s actual processing
    "summarize": 12.0,   # AI summarization (observed avg: 11.5s)
    "embed": 1.5,        # Embedding generation (observed avg: 1.1s)
    "build_relationships": 0.5,  # Relationship building (observed avg: 0.1s)
}

# Default enforced delays (seconds) - intentional waits for rate limiting
# These are shown separately in the UI to explain why transcribe takes so long
DEFAULT_ENFORCED_DELAYS = {
    "transcribe": 65.0,  # yt-dlp subtitle_sleep (60s + avg 5s jitter)
    "summarize": 0.0,
    "embed": 0.0,
    "build_relationships": 0.0,
}

# Transcribe time is mostly FIXED (enforced delay dominates), not duration-proportional
# Only used as a fallback when no history exists
TRANSCRIBE_BASE_TIME = 70.0  # Fixed base time for transcribe

# Minimum number of history records required to use historical averages
MIN_HISTORY_COUNT = 3

# Number of recent jobs to use for rolling average
ROLLING_AVERAGE_COUNT = 50

# How far back to look for historical data
HISTORY_LOOKBACK_DAYS = 30


class StatsService:
    """Service for processing statistics and ETA calculations."""

    def __init__(self, session: AsyncSession):
        """Initialize the stats service.

        Args:
            session: Database session.
        """
        self.session = session

    async def get_average_processing_time(
        self,
        job_type: str,
        video_duration_seconds: int | None = None,
    ) -> float:
        """Get average processing time for a job type.

        Uses rolling average from recent successful jobs.
        Falls back to defaults if insufficient history.
        
        Note: Transcribe time is mostly fixed (enforced delay dominates),
        NOT proportional to video duration.

        Args:
            job_type: Type of job (transcribe, summarize, embed, build_relationships).
            video_duration_seconds: Optional video duration (not used for transcribe).

        Returns:
            Average processing time in seconds.
        """
        # Query recent successful jobs of this type
        cutoff_date = datetime.utcnow() - timedelta(days=HISTORY_LOOKBACK_DAYS)
        
        query = (
            select(
                func.avg(JobHistory.processing_duration_seconds),
                func.count(JobHistory.history_id),
            )
            .where(
                and_(
                    JobHistory.job_type == job_type,
                    JobHistory.success == True,
                    JobHistory.completed_at >= cutoff_date,
                )
            )
        )
        
        result = await self.session.execute(query)
        row = result.one()
        avg_duration, count = row[0], row[1]
        
        if count < MIN_HISTORY_COUNT:
            # Not enough history, use defaults
            return DEFAULT_PROCESSING_TIMES.get(job_type, 30.0)
        
        # Use historical average directly
        # Note: We don't scale transcribe by video duration because the enforced
        # delay (~65s) dominates and is not proportional to video length
        return float(avg_duration) if avg_duration else DEFAULT_PROCESSING_TIMES.get(job_type, 30.0)

    async def get_all_average_processing_times(
        self,
        video_duration_seconds: int | None = None,
    ) -> dict[str, float]:
        """Get average processing times for all job types.
        
        Args:
            video_duration_seconds: Optional video duration (not used for transcribe).

        Returns:
            Dict mapping job_type to average duration in seconds.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=HISTORY_LOOKBACK_DAYS)
        
        query = (
            select(
                JobHistory.job_type,
                func.avg(JobHistory.processing_duration_seconds),
                func.count(JobHistory.history_id),
            )
            .where(
                and_(
                    JobHistory.success == True,
                    JobHistory.completed_at >= cutoff_date,
                )
            )
            .group_by(JobHistory.job_type)
        )
        
        result = await self.session.execute(query)
        rows = result.all()
        
        # Start with defaults
        averages = dict(DEFAULT_PROCESSING_TIMES)
        
        # Override with actual data where available
        # Note: We don't scale transcribe by video duration because the enforced
        # delay (~65s) dominates and is not proportional to video length
        for job_type, avg_duration, count in rows:
            if count >= MIN_HISTORY_COUNT and avg_duration:
                averages[job_type] = float(avg_duration)
        
        return averages

    async def get_average_enforced_delays(self) -> dict[str, float]:
        """Get average enforced delays for all job types.
        
        Enforced delays are intentional waits (e.g., yt-dlp subtitle_sleep)
        that are separate from actual processing time.

        Returns:
            Dict mapping job_type to average enforced delay in seconds.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=HISTORY_LOOKBACK_DAYS)
        
        query = (
            select(
                JobHistory.job_type,
                func.avg(JobHistory.enforced_delay_seconds),
                func.count(JobHistory.history_id),
            )
            .where(
                and_(
                    JobHistory.success == True,
                    JobHistory.completed_at >= cutoff_date,
                    JobHistory.enforced_delay_seconds.isnot(None),
                )
            )
            .group_by(JobHistory.job_type)
        )
        
        result = await self.session.execute(query)
        rows = result.all()
        
        # Start with defaults
        delays = dict(DEFAULT_ENFORCED_DELAYS)
        
        # Override with actual data where available
        for job_type, avg_delay, count in rows:
            if count >= MIN_HISTORY_COUNT and avg_delay:
                delays[job_type] = float(avg_delay)
        
        return delays

    async def get_total_estimated_time(
        self,
        job_type: str,
        video_duration_seconds: int | None = None,
    ) -> tuple[float, float, float]:
        """Get total estimated time including processing and enforced delay.
        
        Args:
            job_type: Type of job.
            video_duration_seconds: Optional video duration for scaling.

        Returns:
            Tuple of (total_seconds, processing_seconds, enforced_delay_seconds).
        """
        processing = await self.get_average_processing_time(job_type, video_duration_seconds)
        delays = await self.get_average_enforced_delays()
        enforced_delay = delays.get(job_type, 0.0)
        
        return (processing + enforced_delay, processing, enforced_delay)

    async def get_queue_position(self, video_id: UUID) -> tuple[int, int]:
        """Get queue position for a video.

        Counts videos that are pending or processing that were created before this one.

        Args:
            video_id: The video ID to check.

        Returns:
            Tuple of (position, total_in_queue).
            Position is 1-indexed (1 = you're next).
        """
        # Get the video's created_at timestamp
        video_result = await self.session.execute(
            select(Video.created_at).where(Video.video_id == video_id)
        )
        video_row = video_result.one_or_none()
        
        if not video_row:
            return (0, 0)
        
        video_created_at = video_row[0]
        
        # Count videos ahead in queue (pending/processing, created before this one)
        ahead_query = (
            select(func.count(Video.video_id))
            .where(
                and_(
                    Video.processing_status.in_(["pending", "processing", "transcribing", "summarizing", "embedding", "building_relationships", "rate_limited"]),
                    Video.created_at < video_created_at,
                )
            )
        )
        ahead_result = await self.session.execute(ahead_query)
        videos_ahead = ahead_result.scalar() or 0
        
        # Count total videos in queue
        total_query = (
            select(func.count(Video.video_id))
            .where(
                Video.processing_status.in_(["pending", "processing", "transcribing", "summarizing", "embedding", "building_relationships", "rate_limited"])
            )
        )
        total_result = await self.session.execute(total_query)
        total_in_queue = total_result.scalar() or 0
        
        # Position is videos_ahead + 1 (1-indexed)
        position = videos_ahead + 1
        
        # Ensure position is consistent with total
        # (race condition: a video may have completed between queries)
        if position > total_in_queue and total_in_queue > 0:
            position = total_in_queue
            videos_ahead = position - 1
        
        return (position, total_in_queue)

    async def estimate_queue_wait(self) -> float:
        """Estimate queue wait time for a new video being submitted.
        
        Returns:
            Estimated wait time in seconds based on videos currently in queue.
        """
        # Count videos currently processing or pending
        # Note: This is called after the new video is inserted but before commit,
        # so we need to subtract 1 to exclude the current video from the count
        processing_query = (
            select(func.count(Video.video_id))
            .where(
                Video.processing_status.in_(["pending", "processing", "transcribing", "summarizing", "embedding", "building_relationships", "rate_limited"])
            )
        )
        result = await self.session.execute(processing_query)
        videos_in_queue = result.scalar() or 0
        
        # Subtract 1 because the current video is already counted
        videos_ahead = max(0, videos_in_queue - 1)
        
        if videos_ahead == 0:
            return 0.0
        
        # Get average times for all stages
        averages = {}
        for stage in ["transcribe", "summarize", "embed", "build_relationships"]:
            averages[stage] = await self.get_average_processing_time(stage)
        
        # Full processing time per video
        full_video_time = sum(averages.values())
        
        return videos_ahead * full_video_time

    async def calculate_eta(
        self,
        video_id: UUID,
        current_job_type: str | None = None,
        current_job_started_at: datetime | None = None,
        first_job_started_at: datetime | None = None,
    ) -> dict:
        """Calculate estimated time remaining for a video to complete processing.

        Args:
            video_id: The video ID.
            current_job_type: Currently running job type, if any.
            current_job_started_at: When the current job started.
            first_job_started_at: When the first job started (for UI countdown anchor).

        Returns:
            Dict with eta_seconds, videos_ahead, queue_position, breakdown.
        """
        averages = await self.get_all_average_processing_times()
        position, total_in_queue = await self.get_queue_position(video_id)
        
        # Get this video's jobs
        jobs_result = await self.session.execute(
            select(Job)
            .where(Job.video_id == video_id)
            .order_by(Job.created_at.asc())
        )
        jobs = jobs_result.scalars().all()
        
        # Calculate remaining time for this video
        remaining_seconds = 0.0
        stages_remaining = []
        
        # All possible stages in order
        all_stages = ["transcribe", "summarize", "embed", "build_relationships"]
        completed_stages = {j.job_type for j in jobs if j.status == "succeeded"}
        
        for stage in all_stages:
            if stage in completed_stages:
                continue
            
            stage_time = averages.get(stage, 30.0)
            
            # If this is the current running stage, subtract elapsed time
            if stage == current_job_type and current_job_started_at:
                elapsed = (datetime.utcnow() - current_job_started_at).total_seconds()
                stage_time = max(0, stage_time - elapsed)
            
            remaining_seconds += stage_time
            stages_remaining.append({
                "stage": stage,
                "estimated_seconds": stage_time,
            })
        
        # Add time for videos ahead in queue
        videos_ahead = position - 1  # Position is 1-indexed
        if videos_ahead > 0:
            # Estimate full processing time for each video ahead
            full_video_time = sum(averages.values())
            queue_wait_seconds = videos_ahead * full_video_time
            remaining_seconds += queue_wait_seconds
        else:
            queue_wait_seconds = 0
        
        # Calculate total estimated time and elapsed time
        estimated_total_seconds = int(sum(averages.values()))
        elapsed_seconds = 0
        if current_job_started_at:
            # Elapsed = time since job started + time for already completed stages
            elapsed_from_current = (datetime.utcnow() - current_job_started_at).total_seconds()
            # Add time for completed stages
            for stage in all_stages:
                if stage in completed_stages:
                    elapsed_seconds += int(averages.get(stage, 30.0))
            elapsed_seconds += int(elapsed_from_current)
        
        # Calculate estimated ready datetime
        from datetime import timedelta
        estimated_ready_at = datetime.utcnow() + timedelta(seconds=int(remaining_seconds))
        
        return {
            "estimated_seconds_remaining": int(remaining_seconds),
            "estimated_total_seconds": estimated_total_seconds + int(queue_wait_seconds),
            "estimated_ready_at": estimated_ready_at,
            "elapsed_seconds": elapsed_seconds,
            "processing_started_at": first_job_started_at or current_job_started_at,
            "queue_position": position,
            "total_in_queue": total_in_queue,
            "videos_ahead": videos_ahead,
            "queue_wait_seconds": int(queue_wait_seconds),
            "stages_remaining": stages_remaining,
            "average_times": averages,
        }

    async def record_job_completion(
        self,
        job_id: UUID,
        video_id: UUID,
        job_type: str,
        started_at: datetime,
        completed_at: datetime,
        success: bool,
        retry_count: int = 0,
        video_duration_seconds: int | None = None,
        queued_at: datetime | None = None,
        enforced_delay_seconds: float | None = None,
    ) -> None:
        """Record a job completion in history.

        Args:
            job_id: The job ID.
            video_id: The video ID.
            job_type: Type of job.
            started_at: When the job started.
            completed_at: When the job completed.
            success: Whether the job succeeded.
            retry_count: Number of retries.
            video_duration_seconds: Duration of the video.
            queued_at: When the job was queued (for wait time calculation).
            enforced_delay_seconds: Intentional delay (e.g., yt-dlp subtitle_sleep).
        """
        processing_duration = (completed_at - started_at).total_seconds()
        
        # Calculate wait time if queued_at is provided
        wait_seconds = None
        if queued_at and started_at:
            wait_seconds = (started_at - queued_at).total_seconds()
        
        history = JobHistory(
            job_id=job_id,
            video_id=video_id,
            job_type=job_type,
            video_duration_seconds=video_duration_seconds,
            queued_at=queued_at,
            wait_seconds=wait_seconds,
            enforced_delay_seconds=enforced_delay_seconds,
            processing_duration_seconds=processing_duration,
            started_at=started_at,
            completed_at=completed_at,
            success=success,
            retry_count=retry_count,
        )
        
        self.session.add(history)
        await self.session.flush()
        
        logger.info(
            "Recorded job completion",
            job_id=str(job_id),
            job_type=job_type,
            duration_seconds=processing_duration,
            wait_seconds=wait_seconds,
            enforced_delay_seconds=enforced_delay_seconds,
            success=success,
        )
