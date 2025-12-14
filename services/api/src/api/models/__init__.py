"""Pydantic model modules for the API."""

from .base import ErrorDetail, ErrorResponse, PaginatedResponse, PaginationMeta
from .channel import ChannelCard, ChannelDetailResponse, ChannelListResponse
from .facet import FacetCount, FacetListResponse, FacetType
from .job import (
    JobListFilters,
    JobListResponse,
    JobResponse,
    JobStage,
    JobStatus,
    JobSummaryResponse,
    JobType,
    RetryJobRequest,
    RetryJobResponse,
    VideoJobsProgress,
)
from .library import (
    FacetTag,
    LibraryStatsResponse,
    ProcessingStatusFilter,
    Segment,
    SegmentListResponse,
    SortField,
    SortOrder,
    VideoCard,
    VideoDetailResponse,
    VideoFilterParams,
    VideoListResponse as LibraryVideoListResponse,
)
from .video import (
    ChannelSummary,
    ProcessingStatus,
    ReprocessVideoRequest,
    SubmitVideoRequest,
    SubmitVideoResponse,
    VideoListResponse,
    VideoResponse,
    VideoSummaryResponse,
    extract_youtube_video_id,
)

__all__ = [
    # Base
    "ErrorDetail",
    "ErrorResponse",
    "PaginatedResponse",
    "PaginationMeta",
    # Channel
    "ChannelCard",
    "ChannelDetailResponse",
    "ChannelListResponse",
    "ChannelSummary",
    # Facet
    "FacetCount",
    "FacetListResponse",
    "FacetTag",
    "FacetType",
    # Job
    "JobListFilters",
    "JobListResponse",
    "JobResponse",
    "JobStage",
    "JobStatus",
    "JobSummaryResponse",
    "JobType",
    "RetryJobRequest",
    "RetryJobResponse",
    "VideoJobsProgress",
    # Library
    "LibraryStatsResponse",
    "LibraryVideoListResponse",
    "ProcessingStatusFilter",
    "Segment",
    "SegmentListResponse",
    "SortField",
    "SortOrder",
    "VideoCard",
    "VideoDetailResponse",
    "VideoFilterParams",
    # Video
    "ProcessingStatus",
    "ReprocessVideoRequest",
    "SubmitVideoRequest",
    "SubmitVideoResponse",
    "VideoListResponse",
    "VideoResponse",
    "VideoSummaryResponse",
    "extract_youtube_video_id",
]

