"""Copilot service for query orchestration.

Orchestrates the flow: query → search → LLM → response
Handles uncertainty detection and follow-up generation.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.models import Channel, Segment, Video
    from shared.logging.config import get_logger
except ImportError:
    import logging
    from typing import Any as AnyType
    
    Channel = AnyType
    Segment = AnyType
    Video = AnyType
    
    def get_logger(name):
        return logging.getLogger(name)


from ..models.copilot import (
    CopilotQueryRequest,
    CopilotQueryResponse,
    Evidence,
    QueryScope,
    RecommendedVideo,
    SegmentSearchRequest,
)
from .llm_service import LLMService, get_llm_service
from .search_service import SearchService

logger = get_logger(__name__)


# Thresholds for uncertainty detection
MIN_EVIDENCE_COUNT = 2
MIN_CONFIDENCE_SCORE = 0.7
HIGH_DISTANCE_THRESHOLD = 0.8  # For cosine distance, higher = less similar


class CopilotService:
    """Service for copilot query orchestration."""
    
    def __init__(
        self, 
        session: AsyncSession,
        llm_service: LLMService | None = None,
    ):
        """Initialize the copilot service.
        
        Args:
            session: Database session.
            llm_service: Optional LLM service (uses singleton if not provided).
        """
        self.session = session
        self.search_service = SearchService(session)
        self.llm_service = llm_service or get_llm_service()
    
    async def query(self, request: CopilotQueryRequest) -> CopilotQueryResponse:
        """Execute a copilot query.
        
        Orchestrates:
        1. Get embedding for query
        2. Search for relevant segments
        3. Get related videos
        4. Generate answer with LLM
        5. Format response with citations
        
        Args:
            request: The query request.
            
        Returns:
            The query response with answer, citations, and follow-ups.
        """
        correlation_id = request.correlation_id
        
        logger.info(
            "Processing copilot query",
            query=request.query[:100],
            scope=request.scope.model_dump() if request.scope else None,
            correlation_id=correlation_id,
        )
        
        # Step 1: Get query embedding
        try:
            query_embedding = await self.llm_service.get_embedding(request.query)
        except Exception as e:
            logger.error(f"Failed to get query embedding: {e}")
            return self._create_error_response(
                "Unable to process query. Please try again.",
                request.scope,
                correlation_id,
            )
        
        # Step 2: Search for relevant segments
        segment_request = SegmentSearchRequest(
            query_text=request.query,
            scope=request.scope,
            limit=15,
        )
        
        try:
            segment_results = await self.search_service.search_segments(
                segment_request,
                query_embedding,
            )
        except Exception as e:
            logger.error(f"Segment search failed: {e}")
            return self._create_error_response(
                "Search failed. Please try again.",
                request.scope,
                correlation_id,
            )
        
        # Step 3: Check for uncertainty (not enough evidence)
        segments = segment_results.segments
        uncertainty = self._detect_uncertainty(segments)
        
        if uncertainty and len(segments) == 0:
            return CopilotQueryResponse(
                answer="I don't have any information on this topic in your library.",
                video_cards=[],
                evidence=[],
                scope_echo=request.scope,
                followups=[
                    "Try broadening your search scope",
                    "Consider ingesting more related videos",
                ],
                uncertainty=uncertainty,
                correlation_id=correlation_id,
            )
        
        # Step 4: Build evidence for LLM
        evidence_for_llm = [
            {
                "video_id": str(seg.video_id),
                "video_title": seg.video_title,
                "channel_name": seg.channel_name,
                "text": seg.text,
                "start_time": seg.start_time,
                "end_time": seg.end_time,
                "youtube_url": seg.youtube_url,
                "score": seg.score,
            }
            for seg in segments
        ]
        
        # Step 5: Generate answer with LLM
        try:
            llm_result = await self.llm_service.generate_answer(
                query=request.query,
                evidence=evidence_for_llm,
            )
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._create_error_response(
                "Failed to generate answer. Please try again.",
                request.scope,
                correlation_id,
            )
        
        # Step 6: Build evidence citations
        evidence = [
            Evidence(
                video_id=seg.video_id,
                youtube_video_id=self._extract_youtube_id(seg.youtube_url),
                video_title=seg.video_title,
                segment_id=seg.segment_id,
                segment_text=seg.text,
                start_time=seg.start_time,
                end_time=seg.end_time,
                youtube_url=seg.youtube_url,
                confidence=1.0 - min(seg.score, 1.0),  # Convert distance to confidence
            )
            for seg in segments[:5]  # Top 5 as citations
        ]
        
        # Step 7: Build video cards (deduplicated by video_id)
        seen_videos: set[UUID] = set()
        video_cards: list[RecommendedVideo] = []
        
        for seg in segments:
            if seg.video_id not in seen_videos and len(video_cards) < 5:
                seen_videos.add(seg.video_id)
                video_cards.append(RecommendedVideo(
                    video_id=seg.video_id,
                    youtube_video_id=self._extract_youtube_id(seg.youtube_url),
                    title=seg.video_title,
                    channel_name=seg.channel_name,
                    thumbnail_url=None,  # Would need to fetch from DB
                    duration=None,
                    relevance_score=1.0 - min(seg.score, 1.0),
                    primary_reason=f"Contains relevant content at {self._format_timestamp(seg.start_time)}",
                ))
        
        # Step 8: Get follow-ups from LLM result or generate new ones
        followups = llm_result.get("follow_ups", [])
        
        if not followups:
            try:
                followups = await self.llm_service.generate_follow_ups(
                    query=request.query,
                    answer=llm_result.get("answer", ""),
                )
            except Exception as e:
                logger.warning(f"Failed to generate follow-ups: {e}")
                followups = self._generate_default_followups(request.scope)
        
        # Step 9: Build final response
        return CopilotQueryResponse(
            answer=llm_result.get("answer", "Unable to generate answer."),
            video_cards=video_cards,
            evidence=evidence,
            scope_echo=request.scope,
            followups=followups,
            uncertainty=llm_result.get("uncertainty") or uncertainty,
            correlation_id=correlation_id,
        )
    
    def _detect_uncertainty(self, segments: list[Any]) -> str | None:
        """Detect if there's insufficient evidence to answer.
        
        Args:
            segments: The search result segments.
            
        Returns:
            Uncertainty message if detected, None otherwise.
        """
        if len(segments) == 0:
            return "No relevant content found in your library. Try ingesting more videos on this topic."
        
        if len(segments) < MIN_EVIDENCE_COUNT:
            return f"Limited evidence found ({len(segments)} relevant segment(s)). The answer may be incomplete."
        
        # Check if all results have high distance (low similarity)
        if all(seg.score > HIGH_DISTANCE_THRESHOLD for seg in segments):
            return "The available content has limited relevance to your question. Consider refining your query or ingesting more specific content."
        
        return None
    
    def _create_error_response(
        self,
        message: str,
        scope: QueryScope | None,
        correlation_id: str | None,
    ) -> CopilotQueryResponse:
        """Create an error response.
        
        Args:
            message: The error message.
            scope: The query scope.
            correlation_id: The correlation ID.
            
        Returns:
            Error response.
        """
        return CopilotQueryResponse(
            answer=message,
            video_cards=[],
            evidence=[],
            scope_echo=scope,
            followups=["Try again", "Rephrase your question"],
            uncertainty="An error occurred while processing your query.",
            correlation_id=correlation_id,
        )
    
    def _extract_youtube_id(self, youtube_url: str) -> str:
        """Extract YouTube video ID from URL.
        
        Args:
            youtube_url: The YouTube URL.
            
        Returns:
            The video ID.
        """
        # URL format: https://www.youtube.com/watch?v=VIDEO_ID&t=123s
        if "v=" in youtube_url:
            video_id = youtube_url.split("v=")[1]
            if "&" in video_id:
                video_id = video_id.split("&")[0]
            return video_id
        return ""
    
    def _format_timestamp(self, seconds: float) -> str:
        """Format seconds as MM:SS timestamp.
        
        Args:
            seconds: Time in seconds.
            
        Returns:
            Formatted timestamp.
        """
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}:{secs:02d}"
    
    def _generate_default_followups(self, scope: QueryScope | None) -> list[str]:
        """Generate default follow-up suggestions.
        
        Args:
            scope: The current query scope.
            
        Returns:
            List of default follow-up suggestions.
        """
        suggestions = ["Show me more details on this topic"]
        
        if scope and scope.channels:
            suggestions.append("Find related videos from other channels")
        else:
            suggestions.append("Focus on a specific channel")
        
        suggestions.append("What are the key concepts mentioned?")
        
        return suggestions[:3]
