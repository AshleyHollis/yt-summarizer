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
    created_at: datetime = Field(description="When job was created")


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


class VideoJobsProgress(BaseResponse):
    """Progress of all jobs for a video."""

    video_id: UUID = Field(description="Video ID")
    overall_status: str = Field(description="Overall processing status")
    overall_progress: int = Field(ge=0, le=100, description="Overall progress percentage")
    jobs: list[JobSummaryResponse] = Field(description="Individual job statuses")

    @property
    def is_complete(self) -> bool:
        """Check if all jobs are complete."""
        return all(job.status == JobStatus.SUCCEEDED for job in self.jobs)

    @property
    def has_failed(self) -> bool:
        """Check if any job has failed."""
        return any(job.status == JobStatus.FAILED for job in self.jobs)
