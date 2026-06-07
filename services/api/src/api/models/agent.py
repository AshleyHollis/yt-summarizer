"""Pydantic models for the agent-facing API (/api/v1/agent/*)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SemanticSearchRequest(BaseModel):
    query: str = Field(description="Search query")
    limit: int = Field(default=10, ge=1, le=50, description="Max results")


class SemanticSearchResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    video_id: UUID
    title: str
    snippet: str
    start_time: float
    end_time: float
    youtube_url: str
    score: float


class SemanticSearchResponse(BaseModel):
    results: list[SemanticSearchResult] = Field(default_factory=list)
    total: int
    estimated_tokens: int


class YouTubeSearchResult(BaseModel):
    youtube_video_id: str
    title: str
    channel: str
    duration_seconds: int | None = None
    url: str
    thumbnail_url: str | None = None


class YouTubeSearchResponse(BaseModel):
    results: list[YouTubeSearchResult] = Field(default_factory=list)
    total: int


class AgentSegmentIndex(BaseModel):
    seq: int
    start: float
    end: float
    label: str | None = None


class AgentVideoResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    video_id: UUID
    youtube_video_id: str | None = None
    title: str
    channel_name: str | None = None
    youtube_url: str | None = None
    duration: int | None = None
    summary: str | None = None
    processing_status: str
    segment_count: int
    estimated_tokens: int
    segments_index: list[AgentSegmentIndex] = Field(default_factory=list)


class SegmentDetail(BaseModel):
    seq: int
    text: str
    start_time: float
    end_time: float
    youtube_url: str | None = None


class SegmentRangeResponse(BaseModel):
    video_id: UUID
    segments: list[SegmentDetail] = Field(default_factory=list)
    total: int
    estimated_tokens: int


class AskRequest(BaseModel):
    query: str = Field(description="Question to answer from the transcript library")
    scope: list[str] | None = Field(default=None, description="Optional video/channel IDs to scope")
    max_evidence_segments: int = Field(default=5, ge=1, le=20)


class AskCitation(BaseModel):
    video_id: UUID
    video_title: str
    start_time: float
    end_time: float
    youtube_url: str | None = None
    snippet: str
    confidence: float


class AskResponse(BaseModel):
    answer: str
    citations: list[AskCitation] = Field(default_factory=list)
    estimated_tokens: int


class IngestRequest(BaseModel):
    url: str = Field(description="YouTube video URL to ingest")


class IngestResponse(BaseModel):
    job_id: UUID
    video_id: UUID
    status: str


class JobStatusResponse(BaseModel):
    job_id: UUID
    video_id: UUID | None = None
    status: str
    progress_pct: int = 0
    stages: list[dict] = Field(default_factory=list)
    created_at: str
    updated_at: str
