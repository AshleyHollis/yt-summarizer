"""Job Pydantic models for API requests and responses."""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from .base import BaseResponse, PaginatedResponse, TimestampMixin


class JobType(str, Enum):
    """Types of processing jobs."""

    TRANSCRIBE = "transcribe"
    SUMMARIZE = "summarize"
    EMBED = "embed"
    BUILD_RELATIONSHIPS = "build_relationships"


class JobStage(str, Enum):
    """Job execution stages."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTERED = "dead_lettered"
    RATE_LIMITED = "rate_limited"


class JobStatus(str, Enum):
    """Job status values."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class JobResponse(BaseResponse, TimestampMixin):
    """Job response model."""

    job_id: UUID = Field(description="Job ID")
    video_id: UUID = Field(description="Associated video ID")
    batch_id: UUID | None = Field(default=None, description="Associated batch ID")
    job_type: JobType = Field(description="Type of job")
    stage: JobStage = Field(description="Current execution stage")
    status: JobStatus = Field(description="Current status")
    progress: int | None = Field(default=None, ge=0, le=100, description="Progress percentage")
    error_message: str | None = Field(default=None, description="Error message if failed")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    max_retries: int = Field(default=5, description="Maximum retry attempts")
    correlation_id: str = Field(description="Correlation ID for tracing")
    started_at: datetime | None = Field(default=None, description="When job started")
    completed_at: datetime | None = Field(default=None, description="When job completed")


class JobSummaryResponse(BaseResponse):
    """Minimal job response for lists and progress tracking."""

    job_id: UUID = Field(description="Job ID")
    video_id: UUID = Field(description="Associated video ID")
    job_type: JobType = Field(description="Type of job")
    stage: JobStage = Field(description="Current execution stage")
    status: JobStatus = Field(description="Current status")
    progress: int | None = Field(default=None, ge=0, le=100, description="Progress percentage")
    error_message: str | None = Field(default=None, description="Error message if failed")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    created_at: datetime = Field(description="When job was created")
    updated_at: datetime | None = Field(default=None, description="When job was last updated")
    next_retry_at: datetime | None = Field(default=None, description="When the next retry will occur (for rate-limited jobs)")


class JobListResponse(PaginatedResponse[JobSummaryResponse]):
    """Paginated list of jobs."""

    pass


class JobListFilters(BaseModel):
    """Filters for job list endpoint."""

    video_id: UUID | None = Field(default=None, description="Filter by video ID")
    batch_id: UUID | None = Field(default=None, description="Filter by batch ID")
    job_type: JobType | None = Field(default=None, description="Filter by job type")
    status: JobStatus | None = Field(default=None, description="Filter by status")
    stage: JobStage | None = Field(default=None, description="Filter by stage")


class RetryJobRequest(BaseModel):
    """Request to retry a failed job."""

    reset_retries: bool = Field(
        default=False,
        description="Reset retry count to 0",
    )


class RetryJobResponse(BaseResponse):
    """Response after retrying a job."""

    job_id: UUID = Field(description="Job ID")
    status: JobStatus = Field(description="New status")
    message: str = Field(description="Status message")


class StageEstimate(BaseModel):
    """Estimated time for a processing stage."""

    stage: str = Field(description="Stage name")
    estimated_seconds: float = Field(description="Estimated seconds for this stage")


class StageHistoryItem(BaseModel):
    """Historical record of a completed processing stage."""

    stage: str = Field(description="Stage name (transcribe, summarize, embed, build_relationships)")
    stage_label: str = Field(description="Human-readable stage label")
    status: str = Field(description="Final status (succeeded, failed)")
    queued_at: datetime | None = Field(default=None, description="When the job was queued")
    started_at: datetime | None = Field(default=None, description="When the stage started")
    completed_at: datetime | None = Field(default=None, description="When the stage completed")
    wait_seconds: float | None = Field(default=None, description="Time spent waiting in queue before processing")
    estimated_wait_seconds: float | None = Field(
        default=None,
        description="Predicted queue wait time at submission"
    )
    enforced_delay_seconds: float | None = Field(
        default=None,
        description="Intentional delay for rate limiting (e.g., yt-dlp subtitle_sleep)"
    )
    actual_seconds: float | None = Field(default=None, description="Actual processing time in seconds")
    estimated_seconds: float = Field(description="Estimated processing time based on historical averages")
    estimated_delay_seconds: float = Field(
        default=0.0,
        description="Estimated enforced delay based on historical averages"
    )
    variance_seconds: float | None = Field(
        default=None,
        description="Difference between actual and estimated (positive = slower than expected)"
    )
    variance_percent: float | None = Field(
        default=None,
        description="Percentage difference from estimate"
    )
    retry_count: int = Field(default=0, description="Number of retries for this stage")


class VideoProcessingHistory(BaseModel):
    """Complete processing history for a video."""

    video_id: UUID = Field(description="Video ID")
    video_title: str | None = Field(default=None, description="Video title")
    video_duration_seconds: int | None = Field(default=None, description="Video duration in seconds")
    processing_status: str = Field(description="Overall processing status")
    
    # Timing overview
    submitted_at: datetime | None = Field(default=None, description="When the video was first submitted")
    first_job_started_at: datetime | None = Field(default=None, description="When first job started")
    last_job_completed_at: datetime | None = Field(default=None, description="When last job completed")
    total_wait_seconds: float | None = Field(default=None, description="Total time spent waiting in queues")
    total_estimated_wait_seconds: float | None = Field(
        default=None,
        description="Total estimated queue wait time at submission"
    )
    total_enforced_delay_seconds: float | None = Field(
        default=None,
        description="Total intentional delays for rate limiting (e.g., yt-dlp subtitle_sleep)"
    )
    total_actual_seconds: float | None = Field(default=None, description="Total actual processing time")
    total_estimated_seconds: float = Field(description="Total estimated processing time")
    total_estimated_delay_seconds: float = Field(
        default=0.0,
        description="Total estimated enforced delays"
    )
    total_elapsed_seconds: float | None = Field(
        default=None,
        description="Total wall-clock time from submission to completion (includes wait + delay + processing)"
    )
    total_variance_seconds: float | None = Field(
        default=None,
        description="Total variance (positive = slower than expected)"
    )
    
    # Stage breakdown
    stages: list[StageHistoryItem] = Field(default_factory=list, description="History for each stage")
    
    # Stats
    stages_completed: int = Field(default=0, description="Number of stages completed")
    stages_failed: int = Field(default=0, description="Number of stages failed")
    total_retries: int = Field(default=0, description="Total retry attempts across all stages")
    
    # Comparison to average
    faster_than_average: bool | None = Field(
        default=None, 
        description="Whether this video processed faster than average"
    )
    percentile: int | None = Field(
        default=None,
        description="Processing speed percentile (1-100, higher = faster)"
    )


class ETAInfo(BaseModel):
    """Estimated time of arrival information."""

    estimated_seconds_remaining: int = Field(
        description="Total estimated seconds until processing completes"
    )
    estimated_total_seconds: int = Field(
        description="Total estimated processing time for all stages"
    )
    estimated_ready_at: datetime = Field(
        description="Estimated datetime when video will be ready"
    )
    elapsed_seconds: int = Field(
        default=0,
        description="Seconds elapsed since processing started"
    )
    processing_started_at: datetime | None = Field(
        default=None,
        description="When processing first started (for timer continuity)"
    )
    queue_position: int = Field(
        description="Position in the processing queue (1-indexed, 1 = you're next)"
    )
    total_in_queue: int = Field(description="Total videos currently in the queue")
    videos_ahead: int = Field(description="Number of videos ahead in the queue")
    queue_wait_seconds: int = Field(
        description="Estimated seconds waiting for videos ahead"
    )
    stages_remaining: list[StageEstimate] = Field(
        default_factory=list,
        description="Breakdown of remaining stages and their estimates",
    )


class VideoJobsProgress(BaseResponse):
    """Progress of all jobs for a video."""

    video_id: UUID = Field(description="Video ID")
    overall_status: str = Field(description="Overall processing status")
    overall_progress: int = Field(ge=0, le=100, description="Overall progress percentage")
    jobs: list[JobSummaryResponse] = Field(description="Individual job statuses")
    
    # ETA and queue information
    eta: ETAInfo | None = Field(
        default=None,
        description="Estimated time and queue position info (only for in-progress videos)",
    )
    current_stage_name: str | None = Field(
        default=None,
        description="Human-readable name of the current processing stage",
    )

    @property
    def is_complete(self) -> bool:
        """Check if all jobs are complete."""
        return all(job.status == JobStatus.SUCCEEDED for job in self.jobs)

    @property
    def has_failed(self) -> bool:
        """Check if any job has failed."""
        return any(job.status == JobStatus.FAILED for job in self.jobs)
