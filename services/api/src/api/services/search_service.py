"""Search service for vector and text search operations.

Implements semantic search over segment embeddings using SQL Server 2025's
native VECTOR_DISTANCE function for cosine similarity.
Instrumented with OpenTelemetry for distributed tracing.
"""

import time
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Import shared modules
try:
    from shared.db.models import (
        Channel,
        Facet,
        Segment,
        Video,
        VideoFacet,
    )
    from shared.logging.config import get_logger
    from shared.telemetry import add_span_event, get_tracer
except ImportError:
    import logging
    from typing import Any as AnyType
    
    Channel = AnyType
    Facet = AnyType
    Segment = AnyType
    Video = AnyType
    VideoFacet = AnyType
    
    def get_logger(name):
        return logging.getLogger(name)
    
    def get_tracer(name):
        class NoOpSpan:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def set_attribute(self, k, v): pass
            def add_event(self, name, attributes=None): pass
        class NoOpTracer:
            def start_as_current_span(self, name, **kwargs): return NoOpSpan()
        return NoOpTracer()
    
    def add_span_event(span, name, attributes=None): pass


from ..models.copilot import (
    CoverageDateRange,
    CoverageResponse,
    NeighborsResponse,
    NeighborVideo,
    QueryScope,
    RecommendedVideo,
    ScoredSegment,
    SegmentSearchRequest,
    SegmentSearchResponse,
    TopicCount,
    TopicsResponse,
    VideoSearchRequest,
    VideoSearchResponse,
)

logger = get_logger(__name__)

# Get tracer for search operations
_tracer = get_tracer("search_service")


class SearchService:
    """Service for vector and text search operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the search service.
        
        Args:
            session: Database session.
        """
        self.session = session
    
    def _build_scope_filter(self, scope: QueryScope | None) -> list[Any]:
        """Build SQL WHERE clause conditions from QueryScope.
        
        Args:
            scope: The query scope filters.
            
        Returns:
            List of SQLAlchemy filter conditions for Videos.
        """
        conditions = []
        
        if scope is None:
            return conditions
        
        # Filter by channels
        if scope.channels:
            conditions.append(Video.channel_id.in_(scope.channels))
        
        # Filter by specific videos
        if scope.video_ids:
            conditions.append(Video.video_id.in_(scope.video_ids))
        
        # Filter by date range
        if scope.date_range:
            if scope.date_range.from_date:
                conditions.append(
                    Video.publish_date >= datetime.combine(
                        scope.date_range.from_date, 
                        datetime.min.time()
                    )
                )
            if scope.date_range.to_date:
                conditions.append(
                    Video.publish_date <= datetime.combine(
                        scope.date_range.to_date,
                        datetime.max.time()
                    )
                )
        
        return conditions
    
    async def _get_video_ids_for_scope(self, scope: QueryScope | None) -> list[UUID] | None:
        """Get video IDs matching the scope, or None if no scope filters.
        
        Args:
            scope: The query scope filters.
            
        Returns:
            List of video IDs, or None if all videos should be searched.
        """
        conditions = self._build_scope_filter(scope)
        
        # Also filter by facets if specified
        if scope and scope.facets:
            # Get videos with the specified facets
            facet_query = (
                select(VideoFacet.video_id)
                .where(VideoFacet.facet_id.in_(scope.facets))
                .distinct()
            )
            facet_result = await self.session.execute(facet_query)
            facet_video_ids = [row[0] for row in facet_result.fetchall()]
            
            if facet_video_ids:
                conditions.append(Video.video_id.in_(facet_video_ids))
            else:
                # No videos match the facet filter
                return []
        
        if not conditions:
            return None  # No filtering needed
        
        query = select(Video.video_id).where(and_(*conditions))
        result = await self.session.execute(query)
        return [row[0] for row in result.fetchall()]
    
    async def search_segments(
        self, 
        request: SegmentSearchRequest,
        query_embedding: list[float],
    ) -> SegmentSearchResponse:
        """Search for segments using vector similarity.
        
        Uses cosine distance on segment embeddings.
        
        Args:
            request: The search request with query and scope.
            query_embedding: The embedding vector for the query.
            
        Returns:
            Matching segments with similarity scores.
        """
        with _tracer.start_as_current_span(
            "search.vector_segments",
            attributes={
                "search.query_length": len(request.query_text),
                "search.limit": request.limit,
                "search.has_scope": request.scope is not None,
                "search.embedding_dimensions": len(query_embedding),
            },
        ) as span:
            start_time = time.monotonic()
            
            # Get video IDs for scope filtering
            video_ids = await self._get_video_ids_for_scope(request.scope)
            
            if video_ids is not None:
                span.set_attribute("search.scope_video_count", len(video_ids))
                if len(video_ids) == 0:
                    # No videos match the scope
                    span.set_attribute("search.result_count", 0)
                    span.set_attribute("search.fallback", "scope_empty")
                    return SegmentSearchResponse(
                        segments=[],
                        scope_echo=request.scope,
                    )
            
            # Build the vector search query using raw SQL for vector operations
            # SQL Server syntax: VECTOR_DISTANCE('cosine', embedding, @query_vector)
            embedding_str = ",".join(str(x) for x in query_embedding)
            
            # Build WHERE clause for video filtering
            where_clause = ""
            if video_ids is not None:
                video_ids_str = ",".join(f"'{str(vid)}'" for vid in video_ids)
                where_clause = f"WHERE s.video_id IN ({video_ids_str})"
            
            # Execute vector search query
            # Note: This uses SQL Server VECTOR_DISTANCE function
            # We embed the limit directly to avoid SQL parameter issues with VECTOR functions
            limit = int(request.limit)  # Ensure it's an integer
            sql = text(f"""
                SELECT TOP {limit}
                    s.segment_id,
                    s.video_id,
                    v.title as video_title,
                    c.name as channel_name,
                    s.text,
                    s.start_time,
                    s.end_time,
                    v.youtube_video_id,
                    VECTOR_DISTANCE('cosine', s.embedding, CAST('[{embedding_str}]' AS VECTOR(1536))) as distance
                FROM Segments s
                INNER JOIN Videos v ON s.video_id = v.video_id
                INNER JOIN Channels c ON v.channel_id = c.channel_id
                {where_clause}
                ORDER BY distance ASC
            """)
            
            try:
                result = await self.session.execute(sql)
                rows = result.fetchall()
                
                elapsed_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute("search.result_count", len(rows))
                span.set_attribute("search.duration_ms", elapsed_ms)
                if rows:
                    span.set_attribute("search.top_score", float(rows[0].distance) if hasattr(rows[0], 'distance') else 0)
            except Exception as e:
                add_span_event(span, "vector_search_failed", {"error": str(e)})
                span.set_attribute("search.fallback", "text_search")
                logger.warning(f"Vector search failed: {e}. Falling back to text search.")
                # Fallback to text-based search if vector search fails
                return await self._fallback_text_search_segments(request)
            
            segments = []
            for row in rows:
                youtube_url = f"https://www.youtube.com/watch?v={row.youtube_video_id}&t={int(row.start_time)}s"
                
                segments.append(ScoredSegment(
                    segment_id=row.segment_id,
                    video_id=row.video_id,
                    video_title=row.video_title,
                    channel_name=row.channel_name,
                    text=row.text,
                    start_time=row.start_time,
                    end_time=row.end_time,
                    youtube_url=youtube_url,
                    score=row.distance,
                ))
            
            return SegmentSearchResponse(
                segments=segments,
                scope_echo=request.scope,
            )
    
    async def fallback_text_search_segments(
        self, 
        request: SegmentSearchRequest,
    ) -> SegmentSearchResponse:
        """Fallback text search when vector search is not available.
        
        This method is used when embedding generation fails (e.g., no embedding
        model deployed). It performs a simple text-based search instead of
        semantic vector search.
        
        Args:
            request: The search request.
            
        Returns:
            Matching segments based on text similarity.
        """
        return await self._fallback_text_search_segments(request)
    
    async def _fallback_text_search_segments(
        self, 
        request: SegmentSearchRequest,
    ) -> SegmentSearchResponse:
        """Internal fallback text search when vector search is not available.
        
        Extracts keywords from the query and searches for segments containing
        any of them.
        
        Args:
            request: The search request.
            
        Returns:
            Matching segments based on text similarity.
        """
        video_ids = await self._get_video_ids_for_scope(request.scope)
        
        # Extract keywords (remove stop words, keep meaningful terms)
        stop_words = {
            'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
            'should', 'may', 'might', 'must', 'can', 'to', 'of', 'in', 'for',
            'on', 'with', 'at', 'by', 'from', 'up', 'about', 'into', 'through',
            'during', 'before', 'after', 'above', 'below', 'between', 'under',
            'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where',
            'why', 'how', 'all', 'each', 'few', 'more', 'most', 'other', 'some',
            'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than',
            'too', 'very', 'just', 'i', 'me', 'my', 'myself', 'we', 'our',
            'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those',
            'am', 'if', 'or', 'and', 'but', 'as', 'because', 'until', 'while',
        }
        
        # Split query into words and filter
        words = [
            word.lower().strip('?.,!;:')
            for word in request.query_text.split()
            if word.lower().strip('?.,!;:') not in stop_words
            and len(word) > 2
        ]
        
        if not words:
            # No meaningful keywords, return empty
            return SegmentSearchResponse(
                segments=[],
                scope_echo=request.scope,
            )
        
        # Build OR conditions for each keyword
        keyword_conditions = [
            Segment.text.ilike(f"%{word}%")
            for word in words[:5]  # Limit to first 5 keywords
        ]
        
        query = (
            select(Segment, Video, Channel)
            .join(Video, Segment.video_id == Video.video_id)
            .join(Channel, Video.channel_id == Channel.channel_id)
            .where(or_(*keyword_conditions))
        )
        
        if video_ids is not None:
            query = query.where(Segment.video_id.in_(video_ids))
        
        query = query.limit(request.limit)
        
        result = await self.session.execute(query)
        rows = result.fetchall()
        
        segments = []
        for segment, video, channel in rows:
            youtube_url = f"https://www.youtube.com/watch?v={video.youtube_video_id}&t={int(segment.start_time)}s"
            
            segments.append(ScoredSegment(
                segment_id=segment.segment_id,
                video_id=segment.video_id,
                video_title=video.title,
                channel_name=channel.name,
                text=segment.text,
                start_time=segment.start_time,
                end_time=segment.end_time,
                youtube_url=youtube_url,
                score=0.5,  # Arbitrary score for text match
            ))
        
        return SegmentSearchResponse(
            segments=segments,
            scope_echo=request.scope,
        )
    
    async def search_videos(
        self, 
        request: VideoSearchRequest,
    ) -> VideoSearchResponse:
        """Search for videos by title, description, or summary.
        
        Args:
            request: The search request with query and scope.
            
        Returns:
            Matching videos.
        """
        conditions = self._build_scope_filter(request.scope)
        
        # Text search on title and description
        search_term = f"%{request.query_text}%"
        conditions.append(
            or_(
                Video.title.ilike(search_term),
                Video.description.ilike(search_term),
            )
        )
        
        query = (
            select(Video)
            .options(selectinload(Video.channel))
            .where(and_(*conditions))
            .limit(request.limit)
        )
        
        result = await self.session.execute(query)
        videos = result.scalars().all()
        
        recommended = []
        for video in videos:
            recommended.append(RecommendedVideo(
                video_id=video.video_id,
                youtube_video_id=video.youtube_video_id,
                title=video.title,
                channel_name=video.channel.name if video.channel else "Unknown",
                thumbnail_url=video.thumbnail_url,
                duration=video.duration,
                relevance_score=0.8,  # Placeholder
                primary_reason="Matches search query",
            ))
        
        return VideoSearchResponse(
            videos=recommended,
            scope_echo=request.scope,
        )
    
    async def get_topics_in_scope(self, scope: QueryScope | None) -> TopicsResponse:
        """Get topic facets with counts for the given scope.
        
        Args:
            scope: The query scope filters.
            
        Returns:
            Topics/facets with video and segment counts.
        """
        video_ids = await self._get_video_ids_for_scope(scope)
        
        # Build query to get facets with counts
        if video_ids is not None:
            query = (
                select(
                    Facet.facet_id,
                    Facet.name,
                    Facet.facet_type,
                    func.count(func.distinct(VideoFacet.video_id)).label("video_count"),
                )
                .join(VideoFacet, Facet.facet_id == VideoFacet.facet_id)
                .where(VideoFacet.video_id.in_(video_ids))
                .group_by(Facet.facet_id, Facet.name, Facet.facet_type)
                .order_by(func.count(func.distinct(VideoFacet.video_id)).desc())
                .limit(50)
            )
        else:
            query = (
                select(
                    Facet.facet_id,
                    Facet.name,
                    Facet.facet_type,
                    func.count(func.distinct(VideoFacet.video_id)).label("video_count"),
                )
                .join(VideoFacet, Facet.facet_id == VideoFacet.facet_id)
                .group_by(Facet.facet_id, Facet.name, Facet.facet_type)
                .order_by(func.count(func.distinct(VideoFacet.video_id)).desc())
                .limit(50)
            )
        
        result = await self.session.execute(query)
        rows = result.fetchall()
        
        topics = []
        for row in rows:
            topics.append(TopicCount(
                facet_id=row.facet_id,
                name=row.name,
                type=row.facet_type or "topic",
                video_count=row.video_count,
                segment_count=0,  # Would require additional query
            ))
        
        return TopicsResponse(
            topics=topics,
            scope_echo=scope,
        )
    
    async def get_coverage(self, scope: QueryScope | None) -> CoverageResponse:
        """Get library coverage statistics for the given scope.
        
        Args:
            scope: The query scope filters.
            
        Returns:
            Coverage statistics.
        """
        conditions = self._build_scope_filter(scope)
        
        # Count videos
        video_query = select(func.count()).select_from(Video)
        if conditions:
            video_query = video_query.where(and_(*conditions))
        video_result = await self.session.execute(video_query)
        video_count = video_result.scalar() or 0
        
        # Get video IDs for segment count
        video_ids = await self._get_video_ids_for_scope(scope)
        
        # Count segments
        segment_query = select(func.count()).select_from(Segment)
        if video_ids is not None:
            segment_query = segment_query.where(Segment.video_id.in_(video_ids))
        segment_result = await self.session.execute(segment_query)
        segment_count = segment_result.scalar() or 0
        
        # Count channels
        channel_query = select(func.count(func.distinct(Video.channel_id))).select_from(Video)
        if conditions:
            channel_query = channel_query.where(and_(*conditions))
        channel_result = await self.session.execute(channel_query)
        channel_count = channel_result.scalar() or 0
        
        # Get date range
        date_query = (
            select(
                func.min(Video.publish_date).label("earliest"),
                func.max(Video.publish_date).label("latest"),
                func.max(Video.updated_at).label("last_updated"),
            )
            .select_from(Video)
        )
        if conditions:
            date_query = date_query.where(and_(*conditions))
        date_result = await self.session.execute(date_query)
        date_row = date_result.fetchone()
        
        date_range = None
        last_updated = None
        if date_row:
            if date_row.earliest and date_row.latest:
                date_range = CoverageDateRange(
                    earliest=date_row.earliest.date() if hasattr(date_row.earliest, 'date') else date_row.earliest,
                    latest=date_row.latest.date() if hasattr(date_row.latest, 'date') else date_row.latest,
                )
            last_updated = date_row.last_updated
        
        return CoverageResponse(
            video_count=video_count,
            segment_count=segment_count,
            channel_count=channel_count,
            date_range=date_range,
            last_updated_at=last_updated,
            scope_echo=scope,
        )
    
    async def get_neighbors(
        self,
        video_id: UUID,
        relationship_types: list[str] | None = None,
        limit: int = 10,
    ) -> NeighborsResponse:
        """Get related videos from the relationship graph.
        
        Args:
            video_id: The source video ID.
            relationship_types: Filter by relationship types.
            limit: Maximum neighbors to return.
            
        Returns:
            Related videos with relationship info.
        """
        # Import Relationship model
        try:
            from shared.db.models import Relationship
        except ImportError:
            Relationship = None
        
        if Relationship is None:
            return NeighborsResponse(
                source_video_id=video_id,
                neighbors=[],
            )
        
        # Query relationships where this video is the source
        query = (
            select(Relationship, Video, Channel)
            .join(Video, Relationship.target_video_id == Video.video_id)
            .join(Channel, Video.channel_id == Channel.channel_id)
            .where(Relationship.source_video_id == video_id)
        )
        
        if relationship_types:
            query = query.where(Relationship.relationship_type.in_(relationship_types))
        
        query = query.order_by(Relationship.confidence.desc()).limit(limit)
        
        result = await self.session.execute(query)
        rows = result.fetchall()
        
        neighbors = []
        # Valid relationship types from RelationshipType enum
        valid_types = {"series", "progression", "same_topic", "references", "related"}
        
        for rel, video, channel in rows:
            # Map invalid relationship types to valid ones
            rel_type = rel.relationship_type
            if rel_type not in valid_types:
                # Fallback for legacy/invalid types like "semantic_similarity"
                rel_type = "same_topic"
            
            recommended = RecommendedVideo(
                video_id=video.video_id,
                youtube_video_id=video.youtube_video_id,
                title=video.title,
                channel_name=channel.name,
                thumbnail_url=video.thumbnail_url,
                duration=video.duration,
                relevance_score=rel.confidence or 0.5,
                primary_reason=rel.rationale or f"Related via {rel_type}",
            )
            
            neighbors.append(NeighborVideo(
                video=recommended,
                relationship_type=rel_type,
                confidence=rel.confidence or 0.5,
                rationale=rel.rationale,
                evidence_text=None,  # Would require joining to segments
            ))
        
        return NeighborsResponse(
            source_video_id=video_id,
            neighbors=neighbors,
        )
