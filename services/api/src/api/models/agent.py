"""Pydantic models for the agent-facing API (/api/v1/agent/*)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .processing import ProcessingMode


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
    processing_mode: ProcessingMode = Field(
        default=ProcessingMode.TRANSCRIPT_ONLY,
        description="How much processing to run. Agent ingestion defaults to transcript-only.",
    )


class IngestResponse(BaseModel):
    job_id: UUID
    video_id: UUID
    status: str
    processing_mode: ProcessingMode = ProcessingMode.TRANSCRIPT_ONLY


class BatchIngestRequest(BaseModel):
    name: str | None = Field(
        default=None,
        description="Display name for the batch. Defaults to an OpenClaw-generated name.",
    )
    urls: list[str] = Field(
        default_factory=list,
        description="YouTube video URLs to ingest.",
    )
    video_ids: list[str] = Field(
        default_factory=list,
        description="Raw YouTube video IDs to ingest.",
    )
    channel_url: str | None = Field(
        default=None,
        description="Optional YouTube channel URL to fetch candidate videos from.",
    )
    channel_limit: int = Field(
        default=25,
        ge=1,
        le=200,
        description="Maximum number of videos to fetch from channel_url.",
    )
    processing_mode: ProcessingMode = Field(
        default=ProcessingMode.TRANSCRIPT_ONLY,
        description="How much processing to run. Agent batch ingestion defaults to transcript-only.",
    )


class KnowledgeSource(BaseModel):
    video_id: UUID
    youtube_video_id: str
    title: str
    channel_name: str | None = None
    youtube_url: str
    segment_count: int


class KnowledgeExtractRequest(BaseModel):
    video_ids: list[UUID] = Field(
        min_length=1,
        max_length=5,
        description="One to five ingested video IDs to distill into an Obsidian-ready note.",
    )
    topic: str | None = Field(
        default=None,
        description="Optional topic or angle to focus the extracted knowledge on.",
    )
    para_destination: str = Field(
        default="Resources/YouTube",
        description="PARA destination folder to suggest for the Obsidian note.",
    )
    note_title: str | None = Field(
        default=None,
        description="Optional note title. If omitted, the LLM proposes one.",
    )
    max_segments_per_video: int = Field(
        default=120,
        ge=10,
        le=300,
        description="Maximum transcript segments per video to include in the extraction prompt.",
    )


class KnowledgeExtractResponse(BaseModel):
    title: str
    para_path: str
    markdown: str
    tags: list[str] = Field(default_factory=list)
    sources: list[KnowledgeSource] = Field(default_factory=list)
    estimated_tokens: int


class JobStatusResponse(BaseModel):
    job_id: UUID
    video_id: UUID | None = None
    status: str
    progress_pct: int = 0
    stages: list[dict] = Field(default_factory=list)
    created_at: str
    updated_at: str
