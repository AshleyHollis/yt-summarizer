"""Pydantic model modules for the API."""

from .base import ErrorDetail, ErrorResponse, PaginatedResponse, PaginationMeta
from .batch import (
    BatchDetailResponse,
    BatchItem,
    BatchItemStatus,
    BatchListResponse,
    BatchResponse,
    BatchRetryResponse,
    BatchStatus,
    CreateBatchRequest,
)
from .channel import (
    ChannelCard,
    ChannelDetailResponse,
    ChannelListResponse,
    ChannelVideo,
    ChannelVideosResponse,
    FetchChannelRequest,
)
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
from .synthesis import (
    LearningPath,
    LearningPathEvidence,
    LearningPathItem,
    Priority,
    SynthesisType,
    SynthesizeRequest,
    SynthesizeResponse,
    WatchList,
    WatchListItem,
)

__all__ = [
    # Base
    "ErrorDetail",
    "ErrorResponse",
    "PaginatedResponse",
    "PaginationMeta",
    # Batch
    "BatchDetailResponse",
    "BatchItem",
    "BatchItemStatus",
    "BatchListResponse",
    "BatchResponse",
    "BatchRetryResponse",
    "BatchStatus",
    "CreateBatchRequest",
    # Channel
    "ChannelCard",
    "ChannelDetailResponse",
    "ChannelListResponse",
    "ChannelSummary",
    "ChannelVideo",
    "ChannelVideosResponse",
    "FetchChannelRequest",
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
    # Synthesis
    "LearningPath",
    "LearningPathEvidence",
    "LearningPathItem",
    "Priority",
    "SynthesisType",
    "SynthesizeRequest",
    "SynthesizeResponse",
    "WatchList",
    "WatchListItem",
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

