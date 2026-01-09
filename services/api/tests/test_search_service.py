"""Unit tests for search service.

These tests verify the search service vector and text search operations.
Uses mocking to avoid database dependencies.
"""

from datetime import date, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from api.models.copilot import (
    CoverageDateRange,
    CoverageResponse,
    DateRange,
    NeighborsResponse,
    NeighborVideo,
    QueryScope,
    RecommendedVideo,
    RelationshipType,
    ScoredSegment,
    SegmentSearchRequest,
    SegmentSearchResponse,
    TopicCount,
    TopicsResponse,
    VideoSearchRequest,
    VideoSearchResponse,
)
from api.services.search_service import SearchService

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def search_service(mock_session):
    """Create a SearchService with mock session."""
    return SearchService(mock_session)


@pytest.fixture
def sample_video_id():
    """Generate a sample video ID."""
    return uuid4()


@pytest.fixture
def sample_channel_id():
    """Generate a sample channel ID."""
    return uuid4()


@pytest.fixture
def sample_facet_id():
    """Generate a sample facet ID."""
    return uuid4()


@pytest.fixture
def sample_embedding():
    """Create a sample embedding vector."""
    # 1536-dimensional vector (OpenAI text-embedding-3-small)
    return [0.1] * 1536


@pytest.fixture
def sample_scope(sample_channel_id):
    """Create a sample query scope."""
    return QueryScope(
        channels=[sample_channel_id],
        date_range=DateRange(
            from_date=date(2024, 1, 1),
            to_date=date(2024, 12, 31),
        ),
    )


# ============================================================================
# Scope Filter Tests
# ============================================================================


class TestScopeFilter:
    """Tests for scope filter building."""
    
    def test_build_scope_filter_empty(self, search_service):
        """Test building filter with no scope."""
        conditions = search_service._build_scope_filter(None)
        assert conditions == []
    
    def test_build_scope_filter_empty_scope(self, search_service):
        """Test building filter with empty scope."""
        scope = QueryScope()
        conditions = search_service._build_scope_filter(scope)
        assert conditions == []
    
    def test_build_scope_filter_with_channels(self, search_service, sample_channel_id):
        """Test building filter with channel filter."""
        scope = QueryScope(channels=[sample_channel_id])
        conditions = search_service._build_scope_filter(scope)
        
        # Should have one condition for channel filtering
        assert len(conditions) == 1
    
    def test_build_scope_filter_with_video_ids(self, search_service, sample_video_id):
        """Test building filter with video ID filter."""
        scope = QueryScope(video_ids=[sample_video_id])
        conditions = search_service._build_scope_filter(scope)
        
        assert len(conditions) == 1
    
    def test_build_scope_filter_with_date_range(self, search_service):
        """Test building filter with date range."""
        scope = QueryScope(
            date_range=DateRange(
                from_date=date(2024, 1, 1),
                to_date=date(2024, 12, 31),
            )
        )
        conditions = search_service._build_scope_filter(scope)
        
        # Should have two conditions: from and to date
        assert len(conditions) == 2
    
    def test_build_scope_filter_with_from_date_only(self, search_service):
        """Test building filter with only from date."""
        scope = QueryScope(
            date_range=DateRange(
                from_date=date(2024, 1, 1),
                to_date=None,
            )
        )
        conditions = search_service._build_scope_filter(scope)
        
        assert len(conditions) == 1
    
    def test_build_scope_filter_with_to_date_only(self, search_service):
        """Test building filter with only to date."""
        scope = QueryScope(
            date_range=DateRange(
                from_date=None,
                to_date=date(2024, 12, 31),
            )
        )
        conditions = search_service._build_scope_filter(scope)
        
        assert len(conditions) == 1
    
    def test_build_scope_filter_combined(
        self,
        search_service,
        sample_channel_id,
        sample_video_id,
    ):
        """Test building filter with multiple filter types."""
        scope = QueryScope(
            channels=[sample_channel_id],
            video_ids=[sample_video_id],
            date_range=DateRange(
                from_date=date(2024, 1, 1),
                to_date=date(2024, 12, 31),
            ),
        )
        conditions = search_service._build_scope_filter(scope)
        
        # Should have 4 conditions: channels, video_ids, from_date, to_date
        assert len(conditions) == 4


# ============================================================================
# Video IDs for Scope Tests
# ============================================================================


class TestGetVideoIdsForScope:
    """Tests for getting video IDs matching scope."""
    
    @pytest.mark.asyncio
    async def test_get_video_ids_no_scope(self, search_service, mock_session):
        """Test getting video IDs with no scope returns None."""
        result = await search_service._get_video_ids_for_scope(None)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_video_ids_empty_scope(self, search_service, mock_session):
        """Test getting video IDs with empty scope returns None."""
        scope = QueryScope()
        result = await search_service._get_video_ids_for_scope(scope)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_video_ids_with_channels(
        self,
        search_service,
        mock_session,
        sample_channel_id,
        sample_video_id,
    ):
        """Test getting video IDs filtered by channel."""
        # Mock the database response
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [(sample_video_id,)]
        mock_session.execute.return_value = mock_result
        
        scope = QueryScope(channels=[sample_channel_id])
        result = await search_service._get_video_ids_for_scope(scope)
        
        assert result is not None
        assert len(result) == 1
        assert result[0] == sample_video_id
    
    @pytest.mark.asyncio
    async def test_get_video_ids_with_facets_empty(
        self,
        search_service,
        mock_session,
        sample_facet_id,
    ):
        """Test getting video IDs with facets returns empty when no matches."""
        # Mock empty facet results
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        mock_session.execute.return_value = mock_result
        
        scope = QueryScope(facets=[sample_facet_id])
        result = await search_service._get_video_ids_for_scope(scope)
        
        assert result == []


# ============================================================================
# Segment Search Tests
# ============================================================================


class TestSegmentSearch:
    """Tests for segment vector search."""
    
    @pytest.mark.asyncio
    async def test_segment_search_empty_scope_match(
        self,
        search_service,
        mock_session,
        sample_video_id,
        sample_embedding,
    ):
        """Test segment search when scope filter returns no videos."""
        # Mock empty scope filter
        with patch.object(
            search_service,
            "_get_video_ids_for_scope",
            return_value=[],
        ):
            request = SegmentSearchRequest(
                query_text="test query",
                scope=QueryScope(channels=[uuid4()]),
                limit=10,
            )
            
            result = await search_service.search_segments(request, sample_embedding)
            
            assert result.segments == []
            assert result.scope_echo == request.scope
    
    @pytest.mark.asyncio
    async def test_segment_search_request_construction(
        self,
        search_service,
        sample_embedding,
    ):
        """Test segment search request is properly constructed."""
        request = SegmentSearchRequest(
            query_text="Python programming basics",
            limit=25,
        )
        
        assert request.query_text == "Python programming basics"
        assert request.limit == 25
        assert request.scope is None
    
    @pytest.mark.asyncio
    async def test_segment_search_request_with_scope(
        self,
        search_service,
        sample_scope,
        sample_embedding,
    ):
        """Test segment search request with scope."""
        request = SegmentSearchRequest(
            query_text="advanced techniques",
            scope=sample_scope,
            limit=15,
        )
        
        assert request.query_text == "advanced techniques"
        assert request.scope is not None
        assert request.scope.channels is not None


# ============================================================================
# Video Search Tests
# ============================================================================


class TestVideoSearch:
    """Tests for video metadata search."""
    
    @pytest.mark.asyncio
    async def test_video_search_request_construction(self):
        """Test video search request is properly constructed."""
        request = VideoSearchRequest(
            query_text="Python tutorial",
            limit=20,
        )
        
        assert request.query_text == "Python tutorial"
        assert request.limit == 20
        assert request.scope is None
    
    @pytest.mark.asyncio
    async def test_video_search_request_with_scope(
        self,
        sample_scope,
    ):
        """Test video search request with scope."""
        request = VideoSearchRequest(
            query_text="machine learning",
            scope=sample_scope,
            limit=10,
        )
        
        assert request.query_text == "machine learning"
        assert request.scope is not None


# ============================================================================
# Topics Tests
# ============================================================================


class TestGetTopicsInScope:
    """Tests for getting topics within scope."""
    
    @pytest.mark.asyncio
    async def test_topics_response_structure(self, sample_facet_id):
        """Test topics response structure."""
        topic = TopicCount(
            facet_id=sample_facet_id,
            name="Python",
            type="topic",
            video_count=10,
            segment_count=50,
        )
        
        response = TopicsResponse(
            topics=[topic],
            scope_echo=None,
        )
        
        assert len(response.topics) == 1
        assert response.topics[0].name == "Python"
        assert response.topics[0].video_count == 10


# ============================================================================
# Coverage Tests
# ============================================================================


class TestGetCoverage:
    """Tests for getting library coverage statistics."""
    
    @pytest.mark.asyncio
    async def test_coverage_response_structure(self):
        """Test coverage response structure."""
        response = CoverageResponse(
            video_count=100,
            segment_count=1000,
            channel_count=5,
            date_range=CoverageDateRange(
                earliest=date(2024, 1, 1),
                latest=date(2024, 12, 31),
            ),
            last_updated_at=datetime.utcnow(),
            scope_echo=None,
        )
        
        assert response.video_count == 100
        assert response.segment_count == 1000
        assert response.channel_count == 5
        assert response.date_range is not None
        assert response.date_range.earliest == date(2024, 1, 1)


# ============================================================================
# Neighbors Tests
# ============================================================================


class TestGetNeighbors:
    """Tests for getting video neighbors/relationships."""
    
    @pytest.mark.asyncio
    async def test_neighbors_response_structure(self, sample_video_id):
        """Test neighbors response structure."""
        related_video_id = uuid4()
        
        neighbor = NeighborVideo(
            video=RecommendedVideo(
                video_id=related_video_id,
                youtube_video_id="xyz123",
                title="Related Video",
                channel_name="Test Channel",
                thumbnail_url="https://example.com/thumb.jpg",
                duration=300,
                relevance_score=0.85,
                primary_reason="Same topic",
            ),
            relationship_type=RelationshipType.SAME_TOPIC,
            confidence=0.9,
            rationale="Both videos cover Python basics",
        )
        
        response = NeighborsResponse(
            source_video_id=sample_video_id,
            neighbors=[neighbor],
        )
        
        assert response.source_video_id == sample_video_id
        assert len(response.neighbors) == 1
        assert response.neighbors[0].relationship_type == RelationshipType.SAME_TOPIC
        assert response.neighbors[0].confidence == 0.9


# ============================================================================
# Model Serialization Tests
# ============================================================================


class TestModelSerialization:
    """Tests for model serialization with aliases."""
    
    def test_scored_segment_serialization(self, sample_video_id):
        """Test ScoredSegment uses camelCase aliases."""
        segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=sample_video_id,
            video_title="Test Video",
            channel_name="Test Channel",
            text="Sample text",
            start_time=10.0,
            end_time=20.0,
            youtube_url="https://youtube.com/watch?v=abc123&t=10",
            score=0.15,
        )
        
        data = segment.model_dump(by_alias=True)
        
        assert "segmentId" in data
        assert "videoId" in data
        assert "videoTitle" in data
        assert "channelName" in data
        assert "startTime" in data
        assert "endTime" in data
        assert "youTubeUrl" in data
    
    def test_segment_search_response_serialization(self, sample_video_id):
        """Test SegmentSearchResponse serialization."""
        segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=sample_video_id,
            video_title="Test",
            channel_name="Channel",
            text="Text",
            start_time=0.0,
            end_time=10.0,
            youtube_url="https://youtube.com/watch",
            score=0.1,
        )
        
        response = SegmentSearchResponse(
            segments=[segment],
            scope_echo=QueryScope(channels=[uuid4()]),
        )
        
        data = response.model_dump(by_alias=True)
        
        assert "segments" in data
        assert "scopeEcho" in data
        assert data["scopeEcho"] is not None
    
    def test_video_search_response_serialization(self, sample_video_id):
        """Test VideoSearchResponse serialization."""
        video = RecommendedVideo(
            video_id=sample_video_id,
            youtube_video_id="abc123",
            title="Test Video",
            channel_name="Channel",
            thumbnail_url="https://example.com/thumb.jpg",
            duration=300,
            relevance_score=0.9,
            primary_reason="Matches query",
        )
        
        response = VideoSearchResponse(
            videos=[video],
            scope_echo=None,
        )
        
        data = response.model_dump(by_alias=True)
        
        assert "videos" in data
        assert len(data["videos"]) == 1
        assert data["videos"][0]["youTubeVideoId"] == "abc123"
        assert data["videos"][0]["relevanceScore"] == 0.9
        assert data["videos"][0]["primaryReason"] == "Matches query"
    
    def test_coverage_response_serialization(self):
        """Test CoverageResponse serialization."""
        response = CoverageResponse(
            video_count=50,
            segment_count=500,
            channel_count=3,
            date_range=CoverageDateRange(
                earliest=date(2024, 1, 1),
                latest=date(2024, 12, 31),
            ),
            last_updated_at=datetime(2024, 6, 15, 12, 0, 0),
        )
        
        data = response.model_dump(by_alias=True)
        
        assert "videoCount" in data
        assert data["videoCount"] == 50
        assert "segmentCount" in data
        assert data["segmentCount"] == 500
        assert "channelCount" in data
        assert data["channelCount"] == 3
        assert "dateRange" in data
        assert "lastUpdatedAt" in data
    
    def test_topics_response_serialization(self, sample_facet_id):
        """Test TopicsResponse serialization."""
        topic = TopicCount(
            facet_id=sample_facet_id,
            name="Python",
            type="topic",
            video_count=10,
            segment_count=50,
        )
        
        response = TopicsResponse(
            topics=[topic],
            scope_echo=None,
        )
        
        data = response.model_dump(by_alias=True)
        
        assert "topics" in data
        assert len(data["topics"]) == 1
        assert "facetId" in data["topics"][0]
        assert "videoCount" in data["topics"][0]
        assert "segmentCount" in data["topics"][0]
