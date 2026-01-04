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
    AIKnowledgeSettings,
    CopilotQueryRequest,
    CopilotQueryResponse,
    Evidence,
    KeyMoment,
    QueryScope,
    RecommendedVideo,
    SegmentSearchRequest,
    VideoExplanation,
)
from .llm_service import LLMService, get_llm_service
from .search_service import SearchService

logger = get_logger(__name__)


# =============================================================================
# Feature Flags
# =============================================================================

# Enable the new expanded RAG retriever with query expansion, RRF fusion, and MMR
# Set to True to use the new retriever, False to use the legacy approach
USE_EXPANDED_RAG_RETRIEVER = True


# =============================================================================
# Thresholds
# =============================================================================


# Thresholds for uncertainty detection
MIN_EVIDENCE_COUNT = 2
MIN_CONFIDENCE_SCORE = 0.7
HIGH_DISTANCE_THRESHOLD = 0.8  # For cosine distance, higher = less similar

# Minimum relevance threshold for including evidence
# Distance-based: lower distance = higher relevance
# Cosine distance ranges: 0 (identical) to 2 (opposite), 1 = orthogonal
# 
# Setting: 0.8 allows moderately relevant content through to the LLM.
# 
# Rationale: When users ask questions using different vocabulary than the source
# material (e.g., "protests banned" vs "gun buyback scheme"), semantic similarity
# scores in the 0.6-0.8 range are common but still contain relevant answers.
# A threshold of 0.6 was too strict and filtered out valid results.
#
# Trade-off: Higher threshold may occasionally include less relevant content,
# but the LLM can determine what's actually relevant from the context.
MAX_DISTANCE_FOR_RELEVANCE = 0.8


class CopilotService:
    """Service for copilot query orchestration."""
    
    def __init__(
        self, 
        session: AsyncSession,
        llm_service: LLMService | None = None,
        use_expanded_retriever: bool | None = None,
    ):
        """Initialize the copilot service.
        
        Args:
            session: Database session.
            llm_service: Optional LLM service (uses singleton if not provided).
            use_expanded_retriever: Whether to use the expanded RAG retriever.
                                    Defaults to USE_EXPANDED_RAG_RETRIEVER flag.
        """
        self.session = session
        self.search_service = SearchService(session)
        self.llm_service = llm_service or get_llm_service()
        self._use_expanded_retriever = (
            use_expanded_retriever 
            if use_expanded_retriever is not None 
            else USE_EXPANDED_RAG_RETRIEVER
        )
        
        # Lazy-initialize expanded retriever
        self._expanded_retriever = None
    
    @property
    def expanded_retriever(self):
        """Get the expanded RAG retriever (lazy initialization)."""
        if self._expanded_retriever is None:
            from .expanded_rag_retriever import ExpandedRagRetriever
            self._expanded_retriever = ExpandedRagRetriever(
                session=self.session,
                llm_service=self.llm_service,
                use_mmr=True,
            )
        return self._expanded_retriever
    
    async def query(self, request: CopilotQueryRequest) -> CopilotQueryResponse:
        """Execute a copilot query.
        
        Orchestrates:
        1. Retrieve relevant segments (if useVideoContext enabled)
        2. Build evidence for LLM
        3. Generate answer with LLM (respecting AI settings)
        4. Build evidence citations
        5. Format response with citations
        
        AI Settings control:
        - useVideoContext: Whether to search video library for context
        - useLLMKnowledge: Whether LLM can use its general knowledge
        - useWebSearch: Whether to include web search results (not yet implemented)
        
        Args:
            request: The query request.
            
        Returns:
            The query response with answer, citations, and follow-ups.
        """
        correlation_id = request.correlation_id
        
        # Get AI settings with defaults
        ai_settings = request.ai_settings or AIKnowledgeSettings()
        
        logger.info(
            "Processing copilot query",
            query=request.query[:100],
            scope=request.scope.model_dump() if request.scope else None,
            ai_settings=ai_settings.model_dump(),
            use_expanded_retriever=self._use_expanded_retriever,
            correlation_id=correlation_id,
        )
        
        # Step 1: Retrieve relevant segments (only if useVideoContext is enabled)
        relevant_segments = []
        if ai_settings.use_video_context:
            if self._use_expanded_retriever:
                relevant_segments = await self._retrieve_with_expanded_rag(
                    request.query, request.scope, correlation_id
                )
            else:
                relevant_segments = await self._retrieve_legacy(
                    request.query, request.scope, correlation_id
                )
        
        # Handle case where video context is disabled or no results found
        if not relevant_segments:
            if not ai_settings.use_video_context:
                # User explicitly disabled video context
                if not ai_settings.use_llm_knowledge:
                    # Both video context and LLM knowledge disabled - nothing to do
                    return CopilotQueryResponse(
                        answer="I cannot answer this question because both video library search and AI knowledge are disabled. Please enable at least one knowledge source.",
                        video_cards=[],
                        evidence=[],
                        scope_echo=request.scope,
                        ai_settings_echo=ai_settings,
                        followups=["Enable 'Your Videos' to search your library", "Enable 'AI Knowledge' to use general knowledge"],
                        uncertainty="No knowledge sources enabled.",
                        correlation_id=correlation_id,
                    )
                # Only LLM knowledge enabled - generate answer without video context
                return await self._generate_llm_only_response(request, ai_settings, correlation_id)
            else:
                # Video context enabled but no results found
                return CopilotQueryResponse(
                    answer="I don't have any information on this topic in your library.",
                    video_cards=[],
                    evidence=[],
                    scope_echo=request.scope,
                    ai_settings_echo=ai_settings,
                    followups=[
                        "Try broadening your search scope",
                        "Consider ingesting more related videos",
                    ],
                    uncertainty="No relevant content found in the library.",
                    correlation_id=correlation_id,
                )
        
        # Check for uncertainty (not enough evidence)
        uncertainty = self._detect_uncertainty(relevant_segments)
        
        # Step 2: Build evidence for LLM (only relevant segments)
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
            for seg in relevant_segments
        ]
        
        # Step 3: Generate answer with LLM (respecting AI knowledge settings)
        try:
            llm_result = await self.llm_service.generate_answer(
                query=request.query,
                evidence=evidence_for_llm,
                use_llm_knowledge=ai_settings.use_llm_knowledge,
            )
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._create_error_response(
                "Failed to generate answer. Please try again.",
                request.scope,
                correlation_id,
            )
        
        # Step 4: Build evidence citations (only relevant segments)
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
            for seg in relevant_segments[:5]  # Top 5 as citations
        ]
        
        # Step 5: Build video cards (deduplicated by video_id) with explanations
        # Only use relevant segments to avoid showing irrelevant videos
        video_explanations = llm_result.get("video_explanations", {})
        seen_videos: set[UUID] = set()
        video_cards: list[RecommendedVideo] = []
        
        for seg in relevant_segments:
            if seg.video_id not in seen_videos and len(video_cards) < 5:
                seen_videos.add(seg.video_id)
                
                # Try to get explanation from LLM result
                video_id_str = str(seg.video_id)
                explanation = self._build_video_explanation(
                    video_id_str=video_id_str,
                    video_explanations=video_explanations,
                    segment=seg,
                )
                
                video_cards.append(RecommendedVideo(
                    video_id=seg.video_id,
                    youtube_video_id=self._extract_youtube_id(seg.youtube_url),
                    title=seg.video_title,
                    channel_name=seg.channel_name,
                    thumbnail_url=None,  # Would need to fetch from DB
                    duration=None,
                    relevance_score=1.0 - min(seg.score, 1.0),
                    primary_reason=f"Contains relevant content at {self._format_timestamp(seg.start_time)}",
                    explanation=explanation,
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
            ai_settings_echo=ai_settings,
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
    
    async def _generate_llm_only_response(
        self,
        request: CopilotQueryRequest,
        ai_settings: AIKnowledgeSettings,
        correlation_id: str | None,
    ) -> CopilotQueryResponse:
        """Generate a response using only LLM knowledge (no video context).
        
        Used when useVideoContext is disabled but useLLMKnowledge is enabled.
        The LLM answers based on its general training knowledge only.
        
        Args:
            request: The query request.
            ai_settings: AI knowledge settings.
            correlation_id: For tracing.
            
        Returns:
            Response generated purely from LLM knowledge.
        """
        try:
            llm_result = await self.llm_service.generate_answer_without_evidence(
                query=request.query,
                allow_general_knowledge=ai_settings.use_llm_knowledge,
            )
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._create_error_response(
                "Failed to generate answer. Please try again.",
                request.scope,
                correlation_id,
            )
        
        # Get follow-ups
        followups = llm_result.get("follow_ups", [])
        if not followups:
            try:
                followups = await self.llm_service.generate_follow_ups(
                    query=request.query,
                    answer=llm_result.get("answer", ""),
                )
            except Exception as e:
                logger.warning(f"Failed to generate follow-ups: {e}")
                followups = ["Would you like to search your video library for more specific information?"]
        
        return CopilotQueryResponse(
            answer=llm_result.get("answer", "Unable to generate answer."),
            video_cards=[],  # No video context used
            evidence=[],  # No evidence from library
            scope_echo=request.scope,
            ai_settings_echo=ai_settings,
            followups=followups,
            uncertainty="This answer is based on AI's general knowledge only, not your video library.",
            correlation_id=correlation_id,
        )
    
    async def _retrieve_with_expanded_rag(
        self,
        query: str,
        scope: QueryScope | None,
        correlation_id: str | None,
    ) -> list[Any]:
        """Retrieve segments using the expanded RAG retriever.
        
        Uses query expansion, RRF fusion, and MMR diversity for higher recall.
        
        Args:
            query: User's question.
            scope: Optional scope filters.
            correlation_id: For logging.
            
        Returns:
            List of relevant ScoredSegment objects.
        """
        try:
            result = await self.expanded_retriever.retrieve(
                query=query,
                scope=scope,
            )
            
            logger.info(
                "Expanded RAG retrieval complete",
                query_variants=len(result.telemetry.query_variants),
                union_size=result.telemetry.union_size,
                final_size=result.telemetry.final_size,
                use_mmr=result.telemetry.use_mmr,
                correlation_id=correlation_id,
            )
            
            return result.segments
            
        except Exception as e:
            logger.error(f"Expanded RAG retrieval failed: {e}")
            # Fallback to legacy retrieval
            logger.info("Falling back to legacy retrieval")
            return await self._retrieve_legacy(query, scope, correlation_id)
    
    async def _retrieve_legacy(
        self,
        query: str,
        scope: QueryScope | None,
        correlation_id: str | None,
    ) -> list[Any]:
        """Legacy retrieval using simple query expansion (backward compatible).
        
        This is the original retrieval logic before the expanded RAG retriever.
        
        Args:
            query: User's question.
            scope: Optional scope filters.
            correlation_id: For logging.
            
        Returns:
            List of relevant ScoredSegment objects.
        """
        # Step 1: Expand query with related terms
        try:
            expanded_queries = await self.llm_service.expand_query(query)
            logger.info(
                "Query expanded (legacy)",
                original=query[:50],
                expanded_count=len(expanded_queries),
                correlation_id=correlation_id,
            )
        except Exception as e:
            logger.warning(f"Query expansion failed, using original: {e}")
            expanded_queries = [query]
        
        # Step 2: Get embeddings for all queries
        all_segments = []
        seen_segment_ids = set()
        
        for query_text in expanded_queries:
            try:
                query_embedding = await self.llm_service.get_embedding(query_text)
                
                # Search for relevant segments
                segment_request = SegmentSearchRequest(
                    query_text=query_text,
                    scope=scope,
                    limit=10,  # Reduced per-query limit since we're doing multiple queries
                )
                
                segment_results = await self.search_service.search_segments(
                    segment_request,
                    query_embedding,
                )
                
                # Deduplicate by segment_id
                for seg in segment_results.segments:
                    if seg.segment_id not in seen_segment_ids:
                        seen_segment_ids.add(seg.segment_id)
                        all_segments.append(seg)
                        
            except Exception as e:
                logger.warning(f"Search failed for query '{query_text[:30]}': {e}")
                continue
        
        if not all_segments:
            return []
        
        # Sort all segments by score (lower distance = better)
        all_segments.sort(key=lambda s: s.score)
        
        # Take top 20 merged results
        segments = all_segments[:20]
        
        # Filter out low-relevance segments
        relevant_segments = [
            seg for seg in segments
            if seg.score <= MAX_DISTANCE_FOR_RELEVANCE
        ]
        
        logger.info(
            "Legacy retrieval complete",
            total_segments=len(segments),
            relevant_segments=len(relevant_segments),
            correlation_id=correlation_id,
        )
        
        return relevant_segments
    
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
    
    def _build_video_explanation(
        self,
        video_id_str: str,
        video_explanations: dict[str, Any],
        segment: Any,
    ) -> VideoExplanation | None:
        """Build a VideoExplanation from LLM result or fallback to segment data.
        
        Args:
            video_id_str: The video ID as string.
            video_explanations: Dict of video explanations from LLM.
            segment: The scored segment for fallback data.
            
        Returns:
            VideoExplanation or None if not available.
        """
        # Try to get LLM-generated explanation
        llm_explanation = video_explanations.get(video_id_str)
        
        if llm_explanation and isinstance(llm_explanation, dict):
            # Parse key moments from LLM
            key_moments = []
            for km in llm_explanation.get("key_moments", []):
                if isinstance(km, dict):
                    key_moments.append(KeyMoment(
                        timestamp=km.get("timestamp", ""),
                        description=km.get("description", ""),
                        segment_id=None,  # LLM doesn't have segment IDs
                        youtube_url=None,
                    ))
            
            return VideoExplanation(
                summary=llm_explanation.get("summary", "Relevant to your query"),
                key_moments=key_moments,
                related_to=llm_explanation.get("related_to"),
            )
        
        # Fallback: No meaningful explanation available from LLM
        # Return None so the UI doesn't show the "Why this?" button
        # The video is already displayed with its title and primary reason
        return None
    
    def _generate_default_followups(self, scope: QueryScope | None) -> list[str]:
        """Generate default follow-up suggestions.
        
        Args:
            scope: The current query scope.
            
        Returns:
            List of default follow-up suggestions.
        """
        suggestions = ["Can you show me more details on this?"]
        
        if scope and scope.channels:
            suggestions.append("What do other channels say about this?")
        else:
            suggestions.append("Can I focus on a specific channel?")
        
        suggestions.append("What are the key concepts I should know?")
        
        return suggestions[:3]
