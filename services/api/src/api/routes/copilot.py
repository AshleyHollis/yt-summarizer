"""Copilot API routes.

All operations are read-only. The copilot cannot:
- Trigger ingestion or reprocessing
- Modify any data
- Access external content
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.connection import get_session
    from shared.logging.config import get_logger
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")

    import logging

    def get_logger(name):
        return logging.getLogger(name)


from ..middleware.correlation import get_correlation_id
from ..models.copilot import (
    CopilotQueryRequest,
    CopilotQueryResponse,
    CoverageResponse,
    ExplainRequest,
    ExplainResponse,
    NeighborsResponse,
    ScopeRequest,
    SegmentSearchRequest,
    SegmentSearchResponse,
    TopicsResponse,
    VideoSearchRequest,
    VideoSearchResponse,
    WarmingUpResponse,
)
from ..models.synthesis import SynthesizeRequest, SynthesizeResponse
from ..services.copilot_service import CopilotService
from ..services.llm_service import get_llm_service
from ..services.search_service import SearchService
from ..services.synthesis_service import SynthesisService

router = APIRouter(prefix="/api/v1/copilot", tags=["Copilot"])
logger = get_logger(__name__)


def get_search_service(session: AsyncSession = Depends(get_session)) -> SearchService:
    """Dependency to get search service."""
    return SearchService(session)


def get_copilot_service(session: AsyncSession = Depends(get_session)) -> CopilotService:
    """Dependency to get copilot service."""
    return CopilotService(session)


@router.post(
    "/query",
    response_model=CopilotQueryResponse,
    summary="Execute Copilot Query",
    description="""
    Send a natural language query to the copilot with optional scope filters.
    Returns an answer with citations and recommended videos.
    
    **This is a read-only operation.** The copilot cannot:
    - Trigger ingestion or reprocessing
    - Modify any data
    - Access external content
    """,
    responses={
        200: {"description": "Query response with citations"},
        400: {"description": "Invalid query or scope"},
        503: {"model": WarmingUpResponse, "description": "Database warming up"},
    },
)
async def query(
    request_: Request,
    body: CopilotQueryRequest,
    service: CopilotService = Depends(get_copilot_service),
) -> CopilotQueryResponse:
    """Execute a copilot query.

    Searches the library and returns an answer with citations.
    """
    correlation_id = get_correlation_id(request_)

    # Inject correlation ID if not provided
    if not body.correlation_id:
        body = CopilotQueryRequest(
            query=body.query,
            scope=body.scope,
            ai_settings=body.ai_settings,
            conversation_id=body.conversation_id,
            correlation_id=correlation_id,
        )

    try:
        result = await service.query(body)
        return result
    except Exception as e:
        logger.error(f"Query failed: {e}", correlation_id=correlation_id)

        # Check for database warming up
        error_str = str(e).lower()
        if "connection" in error_str or "timeout" in error_str:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=WarmingUpResponse(
                    message="Database is warming up, please retry in a few seconds",
                    retry_after=5,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/search/segments",
    response_model=SegmentSearchResponse,
    summary="Semantic Search Segments",
    description="Search for relevant transcript segments using vector similarity",
)
async def search_segments(
    request_: Request,
    body: SegmentSearchRequest,
    service: SearchService = Depends(get_search_service),
) -> SegmentSearchResponse:
    """Search for segments using vector similarity."""
    correlation_id = get_correlation_id(request_)

    try:
        # Try to get embedding for the query
        llm_service = get_llm_service()
        try:
            query_embedding = await llm_service.get_embedding(body.query_text)
            result = await service.search_segments(body, query_embedding)
        except Exception as embed_error:
            # Embedding failed (e.g., no embedding model deployed)
            # Fall back to text-based search
            logger.warning(
                f"Embedding failed, falling back to text search: {embed_error}",
                correlation_id=correlation_id,
            )
            result = await service.fallback_text_search_segments(body)

        return result
    except Exception as e:
        logger.error(f"Segment search failed: {e}", correlation_id=correlation_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/search/videos",
    response_model=VideoSearchResponse,
    summary="Search Videos by Metadata",
    description="Search for videos matching text in title, description, or summary",
)
async def search_videos(
    request_: Request,
    body: VideoSearchRequest,
    service: SearchService = Depends(get_search_service),
) -> VideoSearchResponse:
    """Search for videos by title, description, or summary."""
    correlation_id = get_correlation_id(request_)

    try:
        result = await service.search_videos(body)
        return result
    except Exception as e:
        logger.error(f"Video search failed: {e}", correlation_id=correlation_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/neighbors/{video_id}",
    response_model=NeighborsResponse,
    summary="Get Related Videos",
    description="Retrieve videos related to a source video via stored relationships",
)
async def get_neighbors(
    video_id: UUID,
    types: list[str] | None = None,
    limit: int = 10,
    service: SearchService = Depends(get_search_service),
) -> NeighborsResponse:
    """Get videos related to a source video."""
    try:
        result = await service.get_neighbors(
            video_id=video_id,
            relationship_types=types,
            limit=min(limit, 50),
        )
        return result
    except Exception as e:
        logger.error(f"Get neighbors failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/topics",
    response_model=TopicsResponse,
    summary="Get Topics in Scope",
    description="Returns facets/topics and their video counts within the given scope",
)
async def get_topics(
    body: ScopeRequest,
    service: SearchService = Depends(get_search_service),
) -> TopicsResponse:
    """Get topic facets with counts for the given scope."""
    try:
        result = await service.get_topics_in_scope(body.scope)
        return result
    except Exception as e:
        logger.error(f"Get topics failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/coverage",
    response_model=CoverageResponse,
    summary="Get Library Coverage",
    description="Returns statistics about indexed content within the given scope",
)
async def get_coverage(
    body: ScopeRequest,
    service: SearchService = Depends(get_search_service),
) -> CoverageResponse:
    """Get library coverage statistics for the given scope."""
    try:
        result = await service.get_coverage(body.scope)
        return result
    except Exception as e:
        logger.error(f"Get coverage failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post(
    "/explain/{video_id}",
    response_model=ExplainResponse,
    summary="Explain Recommendation",
    description="Get detailed explanation of why a video appeared in results",
)
async def explain_recommendation(
    video_id: UUID,
    body: ExplainRequest,
    session: AsyncSession = Depends(get_session),
) -> ExplainResponse:
    """Explain why a video was recommended.

    Note: Full implementation is in US5. This provides basic functionality.
    """
    # Import models
    try:
        from shared.db.models import Relationship, Segment, Video
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Explanation service not available",
        )

    # Get video details
    video_query = select(Video).where(Video.video_id == video_id)
    result = await session.execute(video_query)
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    # Get similarity evidence (top segments if query provided)
    similarity_basis = []
    if body.query_text:
        try:
            llm_service = get_llm_service()
            query_embedding = await llm_service.get_embedding(body.query_text)

            search_service = SearchService(session)
            from ..models.copilot import SegmentSearchRequest, SimilarityEvidence

            segment_request = SegmentSearchRequest(
                query_text=body.query_text,
                scope=body.scope,
                limit=5,
            )
            segment_results = await search_service.search_segments(
                segment_request,
                query_embedding,
            )

            for seg in segment_results.segments:
                if seg.video_id == video_id:
                    similarity_basis.append(
                        SimilarityEvidence(
                            segment_id=seg.segment_id,
                            segment_text=seg.text,
                            start_time=seg.start_time,
                            end_time=seg.end_time,
                            score=seg.score,
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to get similarity evidence: {e}")

    # Get relationship evidence
    relationship_basis = []
    try:
        from ..models.copilot import RelationshipEvidence

        rel_query = (
            select(Relationship, Video)
            .join(Video, Relationship.target_video_id == Video.video_id)
            .where(Relationship.source_video_id == video_id)
            .limit(5)
        )
        rel_result = await session.execute(rel_query)

        for rel, target_video in rel_result.fetchall():
            relationship_basis.append(
                RelationshipEvidence(
                    relationship_type=rel.relationship_type,
                    related_video_id=target_video.video_id,
                    related_video_title=target_video.title,
                    confidence=rel.confidence or 0.5,
                    rationale=rel.rationale,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to get relationship evidence: {e}")

    # Calculate overall confidence
    confidence_scores = [s.score for s in similarity_basis] if similarity_basis else []
    if relationship_basis:
        confidence_scores.extend([r.confidence for r in relationship_basis])

    overall_confidence = 0.5
    if confidence_scores:
        # For similarity, lower score = higher confidence (cosine distance)
        # For relationships, higher confidence = higher confidence
        overall_confidence = min(
            1.0, sum(1 - s if s < 1 else s for s in confidence_scores) / len(confidence_scores)
        )

    return ExplainResponse(
        video_id=video_id,
        video_title=video.title,
        similarity_basis=similarity_basis,
        relationship_basis=relationship_basis,
        overall_confidence=overall_confidence,
    )


def get_synthesis_service(session: AsyncSession = Depends(get_session)) -> SynthesisService:
    """Dependency to get synthesis service."""
    return SynthesisService(session)


@router.post(
    "/synthesize",
    response_model=SynthesizeResponse,
    summary="Synthesize Structured Output",
    description="""
    Synthesize a structured output (learning path or watch list) from library content.
    
    - **learning_path**: Ordered sequence of videos for progressive learning
    - **watch_list**: Prioritized collection based on user interests
    
    Returns synthesized output with rationale for each item and gap detection.
    
    **This is a read-only operation.** The copilot cannot:
    - Trigger ingestion or reprocessing
    - Modify any data
    - Access external content
    """,
    responses={
        200: {"description": "Synthesized output with items and rationale"},
        400: {"description": "Invalid synthesis type or query"},
        422: {"description": "Validation error"},
        503: {"model": WarmingUpResponse, "description": "Database warming up"},
    },
)
async def synthesize(
    request_: Request,
    body: SynthesizeRequest,
    session: AsyncSession = Depends(get_session),
) -> SynthesizeResponse:
    """Synthesize a structured output from library content.

    Creates learning paths or watch lists from indexed videos.
    """
    correlation_id = get_correlation_id(request_)

    # Inject correlation ID if not provided
    if not body.correlation_id:
        body = SynthesizeRequest(
            synthesis_type=body.synthesis_type,
            query=body.query,
            scope=body.scope,
            max_items=body.max_items,
            correlation_id=correlation_id,
        )

    # Validate query is not empty
    if not body.query or not body.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    try:
        service = SynthesisService(session)
        result = await service.synthesize(body)
        return result
    except Exception as e:
        logger.error(f"Synthesis failed: {e}", correlation_id=correlation_id)

        # Check for database warming up
        error_str = str(e).lower()
        if "connection" in error_str or "timeout" in error_str:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=WarmingUpResponse(
                    message="Database is warming up, please retry in a few seconds",
                    retry_after=5,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
