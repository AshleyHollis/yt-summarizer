"""Copilot Pydantic models for API requests and responses.

All copilot operations are read-only. The copilot cannot:
- Trigger ingestion or reprocessing
- Modify any data
- Access external content
"""

from datetime import date, datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .base import BaseResponse


class ContentType(str, Enum):
    """Types of content to search."""
    
    SUMMARY = "summary"
    SEGMENT = "segment"
    RELATIONSHIP = "relationship"


class RelationshipType(str, Enum):
    """Types of relationships between videos."""
    
    SERIES = "series"
    PROGRESSION = "progression"
    SAME_TOPIC = "same_topic"
    REFERENCES = "references"
    RELATED = "related"


class DateRange(BaseModel):
    """Date range filter."""
    
    from_date: date | None = Field(default=None, alias="from", description="Start date (inclusive)")
    to_date: date | None = Field(default=None, alias="to", description="End date (inclusive)")
    
    model_config = {"populate_by_name": True}


class QueryScope(BaseModel):
    """Scope filters for copilot queries.
    
    Allows filtering searches to specific channels, videos, date ranges,
    facets, and content types.
    """
    
    channels: list[UUID] | None = Field(
        default=None,
        description="Filter to specific channels"
    )
    video_ids: list[UUID] | None = Field(
        default=None,
        alias="videoIds",
        description="Filter to specific videos"
    )
    date_range: DateRange | None = Field(
        default=None,
        alias="dateRange",
        description="Filter by publish date range"
    )
    facets: list[UUID] | None = Field(
        default=None,
        description="Filter by facet/tag IDs"
    )
    content_types: list[ContentType] | None = Field(
        default=None,
        alias="contentTypes",
        description="Types of content to search"
    )
    
    model_config = {"populate_by_name": True}


class CopilotQueryRequest(BaseModel):
    """Request to execute a copilot query."""
    
    query: str = Field(
        description="Natural language query",
        examples=["What techniques does he recommend for beginners?"]
    )
    scope: QueryScope | None = Field(
        default=None,
        description="Optional scope filters"
    )
    conversation_id: UUID | None = Field(
        default=None,
        alias="conversationId",
        description="Optional conversation context for multi-turn"
    )
    correlation_id: str | None = Field(
        default=None,
        alias="correlationId",
        description="Correlation ID for tracing"
    )
    
    model_config = {"populate_by_name": True}


class Evidence(BaseModel):
    """Citation evidence supporting an answer."""
    
    video_id: UUID = Field(alias="videoId", description="Internal video ID")
    youtube_video_id: str = Field(alias="youTubeVideoId", description="YouTube video ID")
    video_title: str = Field(alias="videoTitle", description="Video title")
    segment_id: UUID = Field(alias="segmentId", description="Segment ID")
    segment_text: str = Field(alias="segmentText", description="Transcript segment text")
    start_time: float = Field(alias="startTime", description="Start time in seconds")
    end_time: float = Field(alias="endTime", description="End time in seconds")
    youtube_url: str = Field(alias="youTubeUrl", description="YouTube URL with timestamp")
    confidence: float = Field(ge=0, le=1, description="Confidence score 0-1")
    
    model_config = {"populate_by_name": True}


class RecommendedVideo(BaseModel):
    """A recommended video in search results."""
    
    video_id: UUID = Field(alias="videoId", description="Internal video ID")
    youtube_video_id: str = Field(alias="youTubeVideoId", description="YouTube video ID")
    title: str = Field(description="Video title")
    channel_name: str = Field(alias="channelName", description="Channel name")
    thumbnail_url: str | None = Field(default=None, alias="thumbnailUrl", description="Thumbnail URL")
    duration: int | None = Field(default=None, description="Duration in seconds")
    relevance_score: float = Field(
        alias="relevanceScore",
        ge=0,
        le=1,
        description="Relevance score 0-1"
    )
    primary_reason: str = Field(
        alias="primaryReason",
        description="Brief reason for recommendation"
    )
    
    model_config = {"populate_by_name": True}


class CopilotQueryResponse(BaseResponse):
    """Response from a copilot query."""
    
    answer: str = Field(description="Natural language response")
    video_cards: list[RecommendedVideo] = Field(
        default_factory=list,
        alias="videoCards",
        description="Recommended videos"
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Citations supporting the answer"
    )
    scope_echo: QueryScope | None = Field(
        default=None,
        alias="scopeEcho",
        description="The scope that was actually searched"
    )
    followups: list[str] = Field(
        default_factory=list,
        description="Suggested follow-up actions"
    )
    uncertainty: str | None = Field(
        default=None,
        description="Explanation if content was insufficient"
    )
    correlation_id: str | None = Field(
        default=None,
        alias="correlationId"
    )
    
    model_config = {"populate_by_name": True}


# Segment Search Models

class SegmentSearchRequest(BaseModel):
    """Request to search segments semantically."""
    
    query_text: str = Field(alias="queryText", description="Text to search for semantically")
    scope: QueryScope | None = Field(default=None, description="Optional scope filters")
    limit: int = Field(default=10, ge=1, le=50, description="Maximum results to return")
    
    model_config = {"populate_by_name": True}


class ScoredSegment(BaseModel):
    """A segment with similarity score."""
    
    segment_id: UUID = Field(alias="segmentId", description="Segment ID")
    video_id: UUID = Field(alias="videoId", description="Video ID")
    video_title: str = Field(alias="videoTitle", description="Video title")
    channel_name: str = Field(alias="channelName", description="Channel name")
    text: str = Field(description="Segment text")
    start_time: float = Field(alias="startTime", description="Start time in seconds")
    end_time: float = Field(alias="endTime", description="End time in seconds")
    youtube_url: str = Field(alias="youTubeUrl", description="YouTube URL with timestamp")
    score: float = Field(description="Similarity score (lower is more similar for cosine distance)")
    
    model_config = {"populate_by_name": True}


class SegmentSearchResponse(BaseResponse):
    """Response from segment search."""
    
    segments: list[ScoredSegment] = Field(default_factory=list, description="Matching segments")
    scope_echo: QueryScope | None = Field(default=None, alias="scopeEcho")
    
    model_config = {"populate_by_name": True}


# Video Search Models

class VideoSearchRequest(BaseModel):
    """Request to search videos by metadata."""
    
    query_text: str = Field(alias="queryText", description="Text to search in title, description, summary")
    scope: QueryScope | None = Field(default=None, description="Optional scope filters")
    limit: int = Field(default=10, ge=1, le=50, description="Maximum results to return")
    
    model_config = {"populate_by_name": True}


class VideoSearchResponse(BaseResponse):
    """Response from video search."""
    
    videos: list[RecommendedVideo] = Field(default_factory=list, description="Matching videos")
    scope_echo: QueryScope | None = Field(default=None, alias="scopeEcho")
    
    model_config = {"populate_by_name": True}


# Neighbors/Graph Models

class NeighborVideo(BaseModel):
    """A related video from the graph."""
    
    video: RecommendedVideo = Field(description="The related video")
    relationship_type: RelationshipType = Field(
        alias="relationshipType",
        description="Type of relationship"
    )
    confidence: float = Field(ge=0, le=1, description="Confidence score")
    rationale: str | None = Field(default=None, description="Why this relationship exists")
    evidence_text: str | None = Field(
        default=None,
        alias="evidenceText",
        description="Evidence supporting the relationship"
    )
    
    model_config = {"populate_by_name": True}


class NeighborsResponse(BaseResponse):
    """Response from neighbors query."""
    
    source_video_id: UUID = Field(alias="sourceVideoId", description="The source video ID")
    neighbors: list[NeighborVideo] = Field(default_factory=list, description="Related videos")
    
    model_config = {"populate_by_name": True}


# Topics/Facets Models

class ScopeRequest(BaseModel):
    """Request with only scope (for topics, coverage)."""
    
    scope: QueryScope | None = Field(default=None, description="Optional scope filters")


class TopicCount(BaseModel):
    """A topic/facet with counts."""
    
    facet_id: UUID = Field(alias="facetId", description="Facet ID")
    name: str = Field(description="Facet name")
    type: str = Field(description="Facet type (topic, format, level, etc.)")
    video_count: int = Field(alias="videoCount", ge=0, description="Number of videos with this facet")
    segment_count: int = Field(alias="segmentCount", ge=0, description="Number of segments with this facet")
    
    model_config = {"populate_by_name": True}


class TopicsResponse(BaseResponse):
    """Response with topic counts."""
    
    topics: list[TopicCount] = Field(default_factory=list, description="Topics with counts")
    scope_echo: QueryScope | None = Field(default=None, alias="scopeEcho")
    
    model_config = {"populate_by_name": True}


# Coverage Models

class CoverageDateRange(BaseModel):
    """Date range in coverage response."""
    
    earliest: date | None = Field(default=None, description="Earliest video date")
    latest: date | None = Field(default=None, description="Latest video date")


class CoverageResponse(BaseResponse):
    """Response with library coverage statistics."""
    
    video_count: int = Field(alias="videoCount", ge=0, description="Number of indexed videos")
    segment_count: int = Field(alias="segmentCount", ge=0, description="Number of indexed segments")
    channel_count: int = Field(alias="channelCount", ge=0, description="Number of channels")
    date_range: CoverageDateRange | None = Field(
        default=None,
        alias="dateRange",
        description="Date range of indexed content"
    )
    last_updated_at: datetime | None = Field(
        default=None,
        alias="lastUpdatedAt",
        description="When the library was last updated"
    )
    scope_echo: QueryScope | None = Field(default=None, alias="scopeEcho")
    
    model_config = {"populate_by_name": True}


# Explain Models (for US5, but needed for explainRecommendation endpoint)

class ExplainRequest(BaseModel):
    """Request to explain a video recommendation."""
    
    query_text: str | None = Field(
        default=None,
        alias="queryText",
        description="The original query (for context)"
    )
    scope: QueryScope | None = Field(default=None, description="The query scope")
    
    model_config = {"populate_by_name": True}


class SimilarityEvidence(BaseModel):
    """Evidence from semantic similarity."""
    
    segment_id: UUID = Field(alias="segmentId", description="Segment ID")
    segment_text: str = Field(alias="segmentText", description="Segment text")
    start_time: float = Field(alias="startTime", description="Start time in seconds")
    end_time: float = Field(alias="endTime", description="End time in seconds")
    score: float = Field(description="Similarity score")
    
    model_config = {"populate_by_name": True}


class RelationshipEvidence(BaseModel):
    """Evidence from stored relationships."""
    
    relationship_type: str = Field(alias="relationshipType", description="Type of relationship")
    related_video_id: UUID = Field(alias="relatedVideoId", description="Related video ID")
    related_video_title: str = Field(alias="relatedVideoTitle", description="Related video title")
    confidence: float = Field(ge=0, le=1, description="Confidence score")
    rationale: str | None = Field(default=None, description="Why this relationship exists")
    
    model_config = {"populate_by_name": True}


class ExplainResponse(BaseResponse):
    """Response explaining a video recommendation."""
    
    video_id: UUID = Field(alias="videoId", description="Video ID being explained")
    video_title: str = Field(alias="videoTitle", description="Video title")
    similarity_basis: list[SimilarityEvidence] = Field(
        default_factory=list,
        alias="similarityBasis",
        description="Evidence from semantic similarity"
    )
    relationship_basis: list[RelationshipEvidence] = Field(
        default_factory=list,
        alias="relationshipBasis",
        description="Evidence from stored relationships"
    )
    overall_confidence: float = Field(
        alias="overallConfidence",
        ge=0,
        le=1,
        description="Overall confidence score"
    )
    
    model_config = {"populate_by_name": True}


# Warming Up Response (for cold start handling)

class WarmingUpResponse(BaseModel):
    """Response when database is warming up."""
    
    message: str = Field(
        default="Database is warming up, please retry in a few seconds",
        description="User-friendly message"
    )
    retry_after: int = Field(
        default=5,
        alias="retryAfter",
        ge=1,
        description="Suggested retry delay in seconds"
    )
    correlation_id: str | None = Field(default=None, alias="correlationId")
    
    model_config = {"populate_by_name": True}
