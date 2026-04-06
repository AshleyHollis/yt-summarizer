"""Agent-facing API routes for AI agent integration (MCP, OpenClaw, etc.)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

try:
    from shared.db.connection import get_session
    from shared.db.models import Segment, Video
    from shared.logging.config import get_logger
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")

    Video = None
    Segment = None

    import logging

    def get_logger(name):
        return logging.getLogger(name)


from ..dependencies.auth import AuthenticatedUser, require_api_key
from ..models.agent import (
    AgentSegmentIndex,
    AgentVideoResponse,
    AskCitation,
    AskRequest,
    AskResponse,
    IngestRequest,
    IngestResponse,
    JobStatusResponse,
    SegmentDetail,
    SegmentRangeResponse,
    SemanticSearchRequest,
    SemanticSearchResponse,
    SemanticSearchResult,
    YouTubeSearchResponse,
    YouTubeSearchResult,
)
from ..models.copilot import CopilotQueryRequest, SegmentSearchRequest
from ..services.copilot_service import CopilotService
from ..services.search_service import SearchService
from ..services.youtube_service import YouTubeService

router = APIRouter(prefix="/api/v1/agent", tags=["Agent"])
logger = get_logger(__name__)


def get_search_service(session: AsyncSession = Depends(get_session)) -> SearchService:
    return SearchService(session)


def get_copilot_service(session: AsyncSession = Depends(get_session)) -> CopilotService:
    return CopilotService(session)


# ---------------------------------------------------------------------------
# POST /search/semantic
# ---------------------------------------------------------------------------


@router.post(
    "/search/semantic",
    response_model=SemanticSearchResponse,
    summary="Semantic search across transcripts",
)
async def search_semantic(
    body: SemanticSearchRequest,
    user: AuthenticatedUser = Depends(require_api_key),
    search_service: SearchService = Depends(get_search_service),
) -> SemanticSearchResponse:
    """Search the transcript library using semantic/vector similarity."""
    try:
        req = SegmentSearchRequest(query_text=body.query, limit=body.limit)

        # Attempt vector search, fall back to text search if embedding unavailable
        try:
            from ..services.llm_service import get_llm_service

            llm_service = get_llm_service()
            query_embedding = await llm_service.get_embedding(body.query)
            result = await search_service.search_segments(req, query_embedding)
        except Exception:
            result = await search_service.fallback_text_search_segments(req)

        segments = result.segments if hasattr(result, "segments") else []

        results = [
            SemanticSearchResult(
                video_id=s.video_id,
                title=s.video_title,
                snippet=s.text,
                start_time=s.start_time,
                end_time=s.end_time,
                youtube_url=s.youtube_url,
                score=s.score,
            )
            for s in segments
        ]
        estimated_tokens = sum(len(r.snippet) for r in results) // 4
        return SemanticSearchResponse(
            results=results,
            total=len(results),
            estimated_tokens=estimated_tokens,
        )
    except Exception as e:
        logger.error("Semantic search failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# GET /youtube/search
# ---------------------------------------------------------------------------


@router.get(
    "/youtube/search",
    response_model=YouTubeSearchResponse,
    summary="Search YouTube for videos",
)
async def search_youtube(
    q: str = Query(..., description="Search query"),
    limit: int = Query(default=10, ge=1, le=50),
    user: AuthenticatedUser = Depends(require_api_key),
) -> YouTubeSearchResponse:
    """Search YouTube for videos matching a query. Does NOT auto-ingest results."""
    yt_service = YouTubeService()
    raw = await yt_service.search_videos(q, min(limit, 50))
    results = [YouTubeSearchResult(**r) for r in raw]
    return YouTubeSearchResponse(results=results, total=len(results))


# ---------------------------------------------------------------------------
# GET /videos/{video_id}  — agent-optimised (segment index, no full transcript)
# ---------------------------------------------------------------------------


@router.get(
    "/videos/{video_id}",
    response_model=AgentVideoResponse,
    summary="Get video metadata and segment index",
)
async def get_video(
    video_id: UUID,
    user: AuthenticatedUser = Depends(require_api_key),
    session: AsyncSession = Depends(get_session),
) -> AgentVideoResponse:
    """Get video metadata, summary, and lightweight segment index.

    Returns a segment index (seq, start, end, label) but NOT full transcript text.
    Use /videos/{id}/segments for actual text, or /ask for RAG queries.
    """
    video_result = await session.execute(
        select(Video).options(selectinload(Video.channel)).where(Video.video_id == video_id)
    )
    video = video_result.scalar_one_or_none()
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Video {video_id} not found",
        )

    seg_result = await session.execute(
        select(Segment).where(Segment.video_id == video_id).order_by(Segment.sequence_number)
    )
    segments = seg_result.scalars().all()

    segments_index = [
        AgentSegmentIndex(
            seq=s.sequence_number,
            start=s.start_time,
            end=s.end_time,
            label=s.label if hasattr(s, "label") else None,
        )
        for s in segments
    ]

    channel_name = None
    if video.channel:
        channel_name = video.channel.name

    return AgentVideoResponse(
        video_id=video.video_id,
        youtube_video_id=video.youtube_video_id,
        title=video.title or "",
        channel_name=channel_name,
        youtube_url=(
            f"https://www.youtube.com/watch?v={video.youtube_video_id}"
            if video.youtube_video_id
            else None
        ),
        duration=video.duration,
        summary=None,
        processing_status=str(video.processing_status),
        segment_count=len(segments),
        estimated_tokens=0,
        segments_index=segments_index,
    )


# ---------------------------------------------------------------------------
# GET /videos/{video_id}/segments
# ---------------------------------------------------------------------------


@router.get(
    "/videos/{video_id}/segments",
    response_model=SegmentRangeResponse,
    summary="Fetch transcript text for a timestamp range",
)
async def get_segments(
    video_id: UUID,
    start_sec: float | None = Query(default=None, description="Start time in seconds (inclusive)"),
    end_sec: float | None = Query(default=None, description="End time in seconds (exclusive)"),
    user: AuthenticatedUser = Depends(require_api_key),
    session: AsyncSession = Depends(get_session),
) -> SegmentRangeResponse:
    """Fetch transcript text for segments in a timestamp range.

    If start_sec and end_sec are omitted, returns all segments (expensive for long videos).
    """
    video_result = await session.execute(select(Video).where(Video.video_id == video_id))
    video = video_result.scalar_one_or_none()
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Video {video_id} not found",
        )

    query = select(Segment).where(Segment.video_id == video_id)
    if start_sec is not None and end_sec is not None:
        query = query.where(Segment.start_time < end_sec, Segment.end_time > start_sec)
    elif start_sec is not None:
        query = query.where(Segment.end_time > start_sec)
    elif end_sec is not None:
        query = query.where(Segment.start_time < end_sec)
    query = query.order_by(Segment.sequence_number)

    seg_result = await session.execute(query)
    segments = seg_result.scalars().all()

    yt_vid_id = video.youtube_video_id
    details = [
        SegmentDetail(
            seq=s.sequence_number,
            text=s.text,
            start_time=s.start_time,
            end_time=s.end_time,
            youtube_url=(
                f"https://www.youtube.com/watch?v={yt_vid_id}&t={int(s.start_time)}s"
                if yt_vid_id
                else None
            ),
        )
        for s in segments
    ]

    total_text = " ".join(d.text for d in details)
    estimated_tokens = len(total_text) // 4

    return SegmentRangeResponse(
        video_id=video_id,
        segments=details,
        total=len(details),
        estimated_tokens=estimated_tokens,
    )


# ---------------------------------------------------------------------------
# POST /ask  — server-side RAG
# ---------------------------------------------------------------------------


@router.post(
    "/ask",
    response_model=AskResponse,
    summary="Ask a question across the transcript library (RAG)",
)
async def ask(
    body: AskRequest,
    user: AuthenticatedUser = Depends(require_api_key),
    copilot_service: CopilotService = Depends(get_copilot_service),
) -> AskResponse:
    """Answer a natural-language question grounded in the transcript library."""
    try:
        copilot_req = CopilotQueryRequest(
            query=body.query,
            scope=None,
        )
        result = await copilot_service.query(copilot_req)

        # CopilotQueryResponse uses `evidence` (list[Evidence])
        raw_evidence = getattr(result, "evidence", []) or []
        raw_evidence = raw_evidence[: body.max_evidence_segments]

        citations = []
        for c in raw_evidence:
            try:
                citations.append(
                    AskCitation(
                        video_id=c.video_id,
                        video_title=c.video_title,
                        start_time=c.start_time,
                        end_time=c.end_time,
                        youtube_url=c.youtube_url,
                        snippet=c.segment_text,
                        confidence=float(c.confidence),
                    )
                )
            except Exception:
                pass

        answer = getattr(result, "answer", "") or ""
        estimated_tokens = len(answer) // 4 + sum(len(c.snippet) for c in citations) // 4

        return AskResponse(
            answer=answer,
            citations=citations,
            estimated_tokens=estimated_tokens,
        )
    except Exception as e:
        logger.error("Ask query failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# POST /videos  — ingest a new YouTube URL
# ---------------------------------------------------------------------------


@router.post(
    "/videos",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a YouTube video URL (async)",
)
async def ingest_video(
    body: IngestRequest,
    user: AuthenticatedUser = Depends(require_api_key),
    session: AsyncSession = Depends(get_session),
) -> IngestResponse:
    """Submit a YouTube URL for async ingestion. Returns a job_id to poll."""
    try:
        from ..services.video_service import VideoService

        video_service = VideoService(session)
        result = await video_service.submit_video(body.url, correlation_id="agent")

        return IngestResponse(
            job_id=result.job_id,
            video_id=result.video_id,
            status=str(result.status.value)
            if hasattr(result.status, "value")
            else str(result.status),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Ingest failed", url=body.url, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingest failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# GET /jobs/{job_id}  — poll ingestion job status
# ---------------------------------------------------------------------------


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get ingestion job status",
)
async def get_job_status(
    job_id: UUID,
    user: AuthenticatedUser = Depends(require_api_key),
    session: AsyncSession = Depends(get_session),
) -> JobStatusResponse:
    """Poll the status of an ingestion job by job_id."""
    try:
        from ..services.job_service import JobService

        job_service = JobService(session)
        result = await job_service.get_job(job_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} not found",
            )

        return JobStatusResponse(
            job_id=result.job_id,
            video_id=result.video_id,
            status=str(result.status.value)
            if hasattr(result.status, "value")
            else str(result.status),
            progress_pct=result.progress or 0,
            stages=[],
            created_at=str(result.created_at),
            updated_at=str(result.updated_at),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Job status fetch failed", job_id=str(job_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch job status: {str(e)}",
        )
