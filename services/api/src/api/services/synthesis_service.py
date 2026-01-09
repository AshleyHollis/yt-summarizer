"""Synthesis service for learning paths and watch lists (US6).

Orchestrates the creation of structured outputs from library content:
- Learning paths: Ordered sequences of videos for progressive learning
- Watch lists: Prioritized collections based on user interests

Uses the existing search and copilot infrastructure.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import select
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


from ..models.copilot import QueryScope, SegmentSearchRequest
from ..models.synthesis import (
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
from .llm_service import LLMService, get_llm_service
from .search_service import SearchService

logger = get_logger(__name__)


# Minimum number of videos required for meaningful synthesis
MIN_VIDEOS_FOR_LEARNING_PATH = 2
MIN_VIDEOS_FOR_WATCH_LIST = 1

# Minimum video duration for learning paths (exclude shorts)
# Shorts lack sufficient content depth for pedagogical ordering
MIN_DURATION_FOR_LEARNING_PATH = 60  # seconds


class SynthesisService:
    """Service for synthesizing structured outputs from library content."""
    
    def __init__(
        self, 
        session: AsyncSession,
        llm_service: LLMService | None = None,
    ):
        """Initialize the synthesis service.
        
        Args:
            session: Database session.
            llm_service: Optional LLM service (uses singleton if not provided).
        """
        self.session = session
        self.search_service = SearchService(session)
        self.llm_service = llm_service or get_llm_service()
    
    async def synthesize(self, request: SynthesizeRequest) -> SynthesizeResponse:
        """Synthesize a structured output from library content.
        
        Args:
            request: The synthesis request with type, query, and optional scope.
            
        Returns:
            SynthesizeResponse with either learning_path or watch_list.
        """
        correlation_id = request.correlation_id or "unknown"
        
        logger.info(
            "Processing synthesis request",
            synthesis_type=request.synthesis_type.value,
            query=request.query[:100],
            max_items=request.max_items,
            correlation_id=correlation_id,
        )
        
        # Find relevant videos using search
        videos = await self._find_relevant_videos(
            query=request.query,
            scope=request.scope,
            max_items=request.max_items * 2,  # Get more than needed for ranking
            correlation_id=correlation_id,
        )
        
        # For learning paths, filter out shorts (videos under MIN_DURATION_FOR_LEARNING_PATH)
        # Shorts lack sufficient content depth for meaningful pedagogical ordering
        if request.synthesis_type == SynthesisType.LEARNING_PATH:
            original_count = len(videos)
            videos = [
                v for v in videos 
                if (v.get("duration") or 0) >= MIN_DURATION_FOR_LEARNING_PATH
            ]
            filtered_count = original_count - len(videos)
            if filtered_count > 0:
                logger.info(
                    f"Filtered {filtered_count} short videos (< {MIN_DURATION_FOR_LEARNING_PATH}s) from learning path",
                    correlation_id=correlation_id,
                )
        
        # Check if we have enough content
        min_required = (
            MIN_VIDEOS_FOR_LEARNING_PATH 
            if request.synthesis_type == SynthesisType.LEARNING_PATH 
            else MIN_VIDEOS_FOR_WATCH_LIST
        )
        
        if len(videos) < min_required:
            return self._create_insufficient_content_response(
                synthesis_type=request.synthesis_type,
                found_count=len(videos),
                min_required=min_required,
            )
        
        # Synthesize based on type
        if request.synthesis_type == SynthesisType.LEARNING_PATH:
            return await self._synthesize_learning_path(
                videos=videos,
                query=request.query,
                max_items=request.max_items,
                correlation_id=correlation_id,
            )
        else:
            return await self._synthesize_watch_list(
                videos=videos,
                query=request.query,
                max_items=request.max_items,
                correlation_id=correlation_id,
            )
    
    async def _find_relevant_videos(
        self,
        query: str,
        scope: QueryScope | None,
        max_items: int,
        correlation_id: str,
    ) -> list[dict[str, Any]]:
        """Find videos relevant to the synthesis query.
        
        Args:
            query: The user's synthesis query.
            scope: Optional scope filters.
            max_items: Maximum number of videos to return.
            correlation_id: Correlation ID for logging.
            
        Returns:
            List of video dictionaries with metadata.
        """
        try:
            # Use search service to find relevant segments
            search_request = SegmentSearchRequest(
                query_text=query,
                scope=scope,
                top_k=max_items * 3,  # Get more segments to group by video
            )
            
            # Try to get embedding for semantic search
            try:
                query_embedding = await self.llm_service.get_embedding(query)
                search_result = await self.search_service.search_segments(
                    search_request, 
                    query_embedding
                )
            except Exception as embed_error:
                logger.warning(
                    f"Embedding failed, using text search: {embed_error}",
                    correlation_id=correlation_id,
                )
                # Fall back to text-based search
                search_result = await self.search_service.fallback_text_search_segments(
                    search_request
                )
            
            # Group segments by video and rank videos
            video_scores: dict[UUID, dict] = {}
            for segment in search_result.segments:
                video_id = segment.video_id
                if video_id not in video_scores:
                    video_scores[video_id] = {
                        "video_id": video_id,
                        "title": segment.video_title,
                        "channel_name": segment.channel_name,
                        "score": 0.0,
                        "segments": [],
                    }
                video_scores[video_id]["score"] += segment.score
                video_scores[video_id]["segments"].append({
                    "segment_id": segment.segment_id,
                    "text": segment.text,
                    "start_time": segment.start_time,
                    "end_time": segment.end_time,
                    "youtube_url": segment.youtube_url,
                })
            
            # Sort by aggregate score and limit
            sorted_videos = sorted(
                video_scores.values(),
                key=lambda v: v["score"],
                reverse=True,
            )[:max_items]
            
            # Fetch full video details
            enriched_videos = []
            for video_data in sorted_videos:
                video_details = await self._get_video_details(video_data["video_id"])
                if video_details:
                    enriched_videos.append({
                        **video_data,
                        "youtube_video_id": video_details.get("youtube_video_id"),
                        "thumbnail_url": video_details.get("thumbnail_url"),
                        "duration": video_details.get("duration"),
                        "description": video_details.get("description"),
                    })
            
            return enriched_videos
            
        except Exception as e:
            logger.error(
                f"Failed to find relevant videos: {e}",
                correlation_id=correlation_id,
            )
            return []
    
    async def _get_video_details(self, video_id: UUID) -> dict[str, Any] | None:
        """Get full video details from database.
        
        Args:
            video_id: The video ID.
            
        Returns:
            Video details dictionary or None.
        """
        try:
            result = await self.session.execute(
                select(Video).where(Video.video_id == video_id)
            )
            video = result.scalar_one_or_none()
            
            if video:
                return {
                    "video_id": video.video_id,
                    "youtube_video_id": video.youtube_video_id,
                    "title": video.title,
                    "description": video.description,
                    "thumbnail_url": video.thumbnail_url,
                    "duration": video.duration,
                }
            return None
        except Exception as e:
            logger.warning(f"Failed to get video details: {e}")
            return None
    
    async def _synthesize_learning_path(
        self,
        videos: list[dict[str, Any]],
        query: str,
        max_items: int,
        correlation_id: str,
    ) -> SynthesizeResponse:
        """Synthesize a learning path from videos.
        
        Uses LLM to determine optimal ordering based on:
        - Prerequisites and dependencies
        - Complexity progression
        - Topic flow
        
        Args:
            videos: List of relevant videos with metadata.
            query: The user's original query.
            max_items: Maximum number of items to include.
            correlation_id: Correlation ID for logging.
            
        Returns:
            SynthesizeResponse with learning_path populated.
        """
        # Build prompt for LLM to order and explain videos
        video_descriptions = "\n".join([
            f"Video {i+1}: {v['title']} - {v.get('description', 'No description')[:200]}"
            for i, v in enumerate(videos[:max_items])
        ])
        
        system_prompt = """You are a learning path curator. Given a set of videos, create an optimal learning sequence.
Order videos from beginner to advanced. For each video, explain why it should be at that position.

CRITICAL: The "prerequisites" field must contain INTEGER ORDER NUMBERS (e.g., [1] or [1, 2]) of videos that should be watched first.
- Use empty array [] if no videos need to be watched first
- Use [1] if video #1 should be watched first
- Use [1, 2] if videos #1 and #2 should be watched first
- NEVER use text descriptions in prerequisites

Return a JSON object with:
{
  "title": "Learning path title",
  "description": "What this learning path covers",
  "items": [
    {
      "order": 1,
      "video_index": 0,
      "rationale": "Why this video is at this position in the learning sequence",
      "learning_objectives": ["objective1", "objective2"],
      "prerequisites": []
    },
    {
      "order": 2,
      "video_index": 1,
      "rationale": "Why this video follows the previous one",
      "learning_objectives": ["objective3"],
      "prerequisites": [1]
    }
  ],
  "coverage_summary": "Summary of what topics are covered",
  "gaps": ["Topics not covered that might be useful"]
}"""
        
        user_prompt = f"""Create a learning path for: "{query}"

Available videos (numbered 1 to {len(videos[:max_items])}):
{video_descriptions}

Order these videos from beginner to advanced and explain your reasoning.
Remember: prerequisites must be integer order numbers only (e.g., [1] or [1, 2]), not text descriptions."""

        try:
            llm_response = await self.llm_service.generate_structured_output(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            
            # Parse LLM response and build learning path
            learning_path = self._parse_learning_path_response(
                llm_response=llm_response,
                videos=videos,
                query=query,
            )
            
            return SynthesizeResponse(
                synthesis_type=SynthesisType.LEARNING_PATH,
                learning_path=learning_path,
                insufficient_content=False,
            )
            
        except Exception as e:
            logger.error(
                f"Failed to generate learning path with LLM: {e}",
                correlation_id=correlation_id,
            )
            # Fall back to simple ordering by relevance score
            return self._create_simple_learning_path(
                videos=videos[:max_items],
                query=query,
            )
    
    async def _synthesize_watch_list(
        self,
        videos: list[dict[str, Any]],
        query: str,
        max_items: int,
        correlation_id: str,
    ) -> SynthesizeResponse:
        """Synthesize a watch list from videos.
        
        Uses LLM to prioritize and explain recommendations.
        
        Args:
            videos: List of relevant videos with metadata.
            query: The user's original query.
            max_items: Maximum number of items to include.
            correlation_id: Correlation ID for logging.
            
        Returns:
            SynthesizeResponse with watch_list populated.
        """
        # Build prompt for LLM to prioritize and explain
        video_descriptions = "\n".join([
            f"Video {i+1}: {v['title']} - {v.get('description', 'No description')[:200]}"
            for i, v in enumerate(videos[:max_items])
        ])
        
        system_prompt = """You are a content curator. Given a set of videos, create a prioritized watch list.
For each video, assign a priority (high/medium/low) and explain why it's recommended.
Return a JSON object with:
{
  "title": "Watch list title",
  "description": "What this watch list focuses on",
  "items": [
    {
      "video_index": 0,
      "priority": "high",
      "reason": "Why this video is recommended",
      "tags": ["tag1", "tag2"]
    }
  ],
  "criteria": "Criteria used to select these videos",
  "gaps": ["Topics not covered that might be useful"]
}"""
        
        user_prompt = f"""Create a watch list for: "{query}"

Available videos:
{video_descriptions}

Prioritize these videos based on relevance and importance."""

        try:
            llm_response = await self.llm_service.generate_structured_output(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            
            # Parse LLM response and build watch list
            watch_list = self._parse_watch_list_response(
                llm_response=llm_response,
                videos=videos,
                query=query,
            )
            
            return SynthesizeResponse(
                synthesis_type=SynthesisType.WATCH_LIST,
                watch_list=watch_list,
                insufficient_content=False,
            )
            
        except Exception as e:
            logger.error(
                f"Failed to generate watch list with LLM: {e}",
                correlation_id=correlation_id,
            )
            # Fall back to simple prioritization by relevance score
            return self._create_simple_watch_list(
                videos=videos[:max_items],
                query=query,
            )
    
    def _parse_learning_path_response(
        self,
        llm_response: dict[str, Any],
        videos: list[dict[str, Any]],
        query: str,
    ) -> LearningPath:
        """Parse LLM response into a LearningPath object.
        
        Args:
            llm_response: JSON response from LLM.
            videos: Original video list.
            query: User's original query.
            
        Returns:
            LearningPath object.
        """
        items = []
        total_duration = 0
        
        for item_data in llm_response.get("items", []):
            video_index = item_data.get("video_index", 0)
            if video_index < len(videos):
                video = videos[video_index]
                duration = video.get("duration", 0) or 0
                total_duration += duration
                
                # Build evidence from video segments
                evidence = []
                for seg in video.get("segments", [])[:3]:  # Limit to 3 evidence items
                    evidence.append(LearningPathEvidence(
                        video_id=video["video_id"],
                        segment_id=seg.get("segment_id"),
                        segment_text=seg.get("text", "")[:200],
                        youtube_url=seg.get("youtube_url"),
                    ))
                
                # Parse prerequisites - handle both integers and strings gracefully
                raw_prereqs = item_data.get("prerequisites", [])
                parsed_prereqs = []
                for prereq in raw_prereqs:
                    if isinstance(prereq, int):
                        parsed_prereqs.append(prereq)
                    elif isinstance(prereq, str):
                        # Try to parse as integer, skip if not possible
                        try:
                            parsed_prereqs.append(int(prereq))
                        except ValueError:
                            # Skip text-based prerequisites
                            pass
                
                items.append(LearningPathItem(
                    order=item_data.get("order", len(items) + 1),
                    video_id=video["video_id"],
                    youtube_video_id=video.get("youtube_video_id", ""),
                    title=video.get("title", "Unknown"),
                    channel_name=video.get("channel_name", "Unknown"),
                    thumbnail_url=video.get("thumbnail_url"),
                    duration=duration,
                    rationale=item_data.get("rationale", "Relevant to your query"),
                    learning_objectives=item_data.get("learning_objectives", []),
                    prerequisites=parsed_prereqs,
                    evidence=evidence,
                ))
        
        return LearningPath(
            title=llm_response.get("title", f"Learning Path: {query[:50]}"),
            description=llm_response.get("description", f"A curated learning path for {query}"),
            estimated_duration=total_duration,
            items=items,
            coverage_summary=llm_response.get("coverage_summary", ""),
            gaps=llm_response.get("gaps", []),
        )
    
    def _parse_watch_list_response(
        self,
        llm_response: dict[str, Any],
        videos: list[dict[str, Any]],
        query: str,
    ) -> WatchList:
        """Parse LLM response into a WatchList object.
        
        Args:
            llm_response: JSON response from LLM.
            videos: Original video list.
            query: User's original query.
            
        Returns:
            WatchList object.
        """
        items = []
        total_duration = 0
        
        for item_data in llm_response.get("items", []):
            video_index = item_data.get("video_index", 0)
            if video_index < len(videos):
                video = videos[video_index]
                duration = video.get("duration", 0) or 0
                total_duration += duration
                
                priority_str = item_data.get("priority", "medium").lower()
                priority = {
                    "high": Priority.HIGH,
                    "medium": Priority.MEDIUM,
                    "low": Priority.LOW,
                }.get(priority_str, Priority.MEDIUM)
                
                items.append(WatchListItem(
                    video_id=video["video_id"],
                    youtube_video_id=video.get("youtube_video_id", ""),
                    title=video.get("title", "Unknown"),
                    channel_name=video.get("channel_name", "Unknown"),
                    thumbnail_url=video.get("thumbnail_url"),
                    duration=duration,
                    priority=priority,
                    reason=item_data.get("reason", "Relevant to your interests"),
                    tags=item_data.get("tags", []),
                ))
        
        return WatchList(
            title=llm_response.get("title", f"Watch List: {query[:50]}"),
            description=llm_response.get("description", f"Curated videos for {query}"),
            total_duration=total_duration,
            items=items,
            criteria=llm_response.get("criteria", "Videos selected based on relevance"),
            gaps=llm_response.get("gaps", []),
        )
    
    def _create_simple_learning_path(
        self,
        videos: list[dict[str, Any]],
        query: str,
    ) -> SynthesizeResponse:
        """Create a simple learning path without LLM (fallback).
        
        Orders videos by relevance score.
        
        Args:
            videos: List of videos.
            query: User's query.
            
        Returns:
            SynthesizeResponse with learning_path.
        """
        items = []
        total_duration = 0
        
        for i, video in enumerate(videos):
            duration = video.get("duration", 0) or 0
            total_duration += duration
            
            # Build evidence from video segments
            evidence = []
            for seg in video.get("segments", [])[:3]:
                evidence.append(LearningPathEvidence(
                    video_id=video["video_id"],
                    segment_id=seg.get("segment_id"),
                    segment_text=seg.get("text", "")[:200],
                    youtube_url=seg.get("youtube_url"),
                ))
            
            items.append(LearningPathItem(
                order=i + 1,
                video_id=video["video_id"],
                youtube_video_id=video.get("youtube_video_id", ""),
                title=video.get("title", "Unknown"),
                channel_name=video.get("channel_name", "Unknown"),
                thumbnail_url=video.get("thumbnail_url"),
                duration=duration,
                rationale=f"Ranked #{i+1} by relevance to your query",
                learning_objectives=[],
                prerequisites=list(range(1, i + 1)) if i > 0 else [],
                evidence=evidence,
            ))
        
        return SynthesizeResponse(
            synthesis_type=SynthesisType.LEARNING_PATH,
            learning_path=LearningPath(
                title=f"Learning Path: {query[:50]}",
                description=f"Videos ordered by relevance to: {query}",
                estimated_duration=total_duration,
                items=items,
                coverage_summary="Videos ranked by search relevance",
                gaps=[],
            ),
            insufficient_content=False,
        )
    
    def _create_simple_watch_list(
        self,
        videos: list[dict[str, Any]],
        query: str,
    ) -> SynthesizeResponse:
        """Create a simple watch list without LLM (fallback).
        
        Prioritizes by relevance score.
        
        Args:
            videos: List of videos.
            query: User's query.
            
        Returns:
            SynthesizeResponse with watch_list.
        """
        items = []
        total_duration = 0
        
        for i, video in enumerate(videos):
            duration = video.get("duration", 0) or 0
            total_duration += duration
            
            # Assign priority based on position
            if i < len(videos) // 3:
                priority = Priority.HIGH
            elif i < 2 * len(videos) // 3:
                priority = Priority.MEDIUM
            else:
                priority = Priority.LOW
            
            items.append(WatchListItem(
                video_id=video["video_id"],
                youtube_video_id=video.get("youtube_video_id", ""),
                title=video.get("title", "Unknown"),
                channel_name=video.get("channel_name", "Unknown"),
                thumbnail_url=video.get("thumbnail_url"),
                duration=duration,
                priority=priority,
                reason=f"Ranked #{i+1} by relevance to your interests",
                tags=[],
            ))
        
        return SynthesizeResponse(
            synthesis_type=SynthesisType.WATCH_LIST,
            watch_list=WatchList(
                title=f"Watch List: {query[:50]}",
                description=f"Videos curated for: {query}",
                total_duration=total_duration,
                items=items,
                criteria="Videos ranked by search relevance",
                gaps=[],
            ),
            insufficient_content=False,
        )
    
    def _create_insufficient_content_response(
        self,
        synthesis_type: SynthesisType,
        found_count: int,
        min_required: int,
    ) -> SynthesizeResponse:
        """Create a response for insufficient content.
        
        Args:
            synthesis_type: The requested synthesis type.
            found_count: Number of videos found.
            min_required: Minimum required for synthesis.
            
        Returns:
            SynthesizeResponse indicating insufficient content.
        """
        if found_count == 0:
            message = (
                "No matching content found in your library. "
                "Try broadening your scope or ingesting more videos on this topic."
            )
        else:
            message = (
                f"Found {found_count} video(s), but need at least {min_required} "
                f"for a meaningful {synthesis_type.value.replace('_', ' ')}. "
                "Try broadening your scope or ingesting more videos on this topic."
            )
        
        return SynthesizeResponse(
            synthesis_type=synthesis_type,
            learning_path=None,
            watch_list=None,
            insufficient_content=True,
            insufficient_message=message,
        )
