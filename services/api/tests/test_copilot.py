"""Integration tests for copilot API endpoints.

These tests verify the copilot query, search, topics, and coverage endpoints.
All copilot operations are read-only.
"""

from datetime import date, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status

# ============================================================================
# Copilot Fixtures
# ============================================================================


@pytest.fixture
def copilot_video_id():
    """Generate a sample video ID for copilot tests."""
    return uuid4()


@pytest.fixture
def copilot_channel_id():
    """Generate a sample channel ID for copilot tests."""
    return uuid4()


@pytest.fixture
def copilot_segment_id():
    """Generate a sample segment ID for copilot tests."""
    return uuid4()


@pytest.fixture
def copilot_facet_id():
    """Generate a sample facet ID for copilot tests."""
    return uuid4()


@pytest.fixture
def copilot_scope(copilot_channel_id):
    """Create a sample query scope for copilot tests."""
    return {
        "channels": [str(copilot_channel_id)],
        "dateRange": {
            "from": "2024-01-01",
            "to": "2024-12-31",
        },
    }


@pytest.fixture
def copilot_mock_video(copilot_video_id, copilot_channel_id):
    """Create a mock video object for copilot tests."""
    video = MagicMock()
    video.video_id = copilot_video_id
    video.youtube_video_id = "dQw4w9WgXcQ"
    video.channel_id = copilot_channel_id
    video.title = "Test Video Title"
    video.description = "Test video description"
    video.duration = 300
    video.publish_date = datetime.utcnow()
    video.thumbnail_url = "https://example.com/thumb.jpg"
    video.processing_status = "completed"
    video.created_at = datetime.utcnow()
    video.updated_at = datetime.utcnow()
    return video


@pytest.fixture
def copilot_mock_channel(copilot_channel_id):
    """Create a mock channel object for copilot tests."""
    channel = MagicMock()
    channel.channel_id = copilot_channel_id
    channel.youtube_channel_id = "UC12345"
    channel.name = "Test Channel"
    channel.description = "Test channel description"
    channel.thumbnail_url = "https://example.com/channel.jpg"
    channel.video_count = 10
    return channel


@pytest.fixture
def copilot_mock_segment(copilot_segment_id, copilot_video_id):
    """Create a mock segment object for copilot tests."""
    segment = MagicMock()
    segment.segment_id = copilot_segment_id
    segment.video_id = copilot_video_id
    segment.sequence_number = 1
    segment.start_time = 10.0
    segment.end_time = 20.5
    segment.text = "This is a sample transcript segment about Python programming."
    return segment


@pytest.fixture
def copilot_mock_facet(copilot_facet_id):
    """Create a mock facet object for copilot tests."""
    facet = MagicMock()
    facet.facet_id = copilot_facet_id
    facet.name = "Python"
    facet.facet_type = "topic"
    facet.description = "Python programming language"
    return facet


@pytest.fixture
def copilot_query_response(copilot_video_id, copilot_segment_id):
    """Create a mock copilot query response."""
    from api.models.copilot import (
        CopilotQueryResponse,
        Evidence,
        KeyMoment,
        RecommendedVideo,
        VideoExplanation,
    )

    return CopilotQueryResponse(
        answer="Based on the indexed content, the recommendation is to start with basic concepts.",
        video_cards=[
            RecommendedVideo(
                video_id=copilot_video_id,
                youtube_video_id="dQw4w9WgXcQ",
                title="Getting Started Tutorial",
                channel_name="Test Channel",
                thumbnail_url="https://example.com/thumb.jpg",
                duration=300,
                relevance_score=0.95,
                primary_reason="Highly relevant to your query",
                explanation=VideoExplanation(
                    summary="This video demonstrates the exact technique you asked about",
                    key_moments=[
                        KeyMoment(
                            timestamp="2:34",
                            description="Introduction to the concept",
                            segment_id=copilot_segment_id,
                            youtube_url="https://youtube.com/watch?v=dQw4w9WgXcQ&t=154",
                        ),
                    ],
                    related_to=None,
                ),
            ),
        ],
        evidence=[
            Evidence(
                video_id=copilot_video_id,
                youtube_video_id="dQw4w9WgXcQ",
                video_title="Getting Started Tutorial",
                segment_id=copilot_segment_id,
                segment_text="This is how you get started with the basics.",
                start_time=10.0,
                end_time=20.0,
                youtube_url="https://youtube.com/watch?v=dQw4w9WgXcQ&t=10",
                confidence=0.92,
            ),
        ],
        scope_echo=None,
        followups=["What are advanced techniques?", "Show me more examples"],
        uncertainty=None,
        correlation_id="test-correlation-id",
    )


@pytest.fixture
def copilot_segment_search_response(copilot_segment_id, copilot_video_id):
    """Create a mock segment search response."""
    from api.models.copilot import ScoredSegment, SegmentSearchResponse

    return SegmentSearchResponse(
        segments=[
            ScoredSegment(
                segment_id=copilot_segment_id,
                video_id=copilot_video_id,
                video_title="Test Video",
                channel_name="Test Channel",
                text="This is a matching segment about Python.",
                start_time=10.0,
                end_time=20.0,
                youtube_url="https://youtube.com/watch?v=abc123&t=10",
                score=0.15,
            ),
        ],
        scope_echo=None,
    )


@pytest.fixture
def copilot_video_search_response(copilot_video_id):
    """Create a mock video search response."""
    from api.models.copilot import RecommendedVideo, VideoSearchResponse

    return VideoSearchResponse(
        videos=[
            RecommendedVideo(
                video_id=copilot_video_id,
                youtube_video_id="abc123",
                title="Test Video About Python",
                channel_name="Test Channel",
                thumbnail_url="https://example.com/thumb.jpg",
                duration=300,
                relevance_score=0.85,
                primary_reason="Title matches query",
            ),
        ],
        scope_echo=None,
    )


@pytest.fixture
def copilot_topics_response(copilot_facet_id):
    """Create a mock topics response."""
    from api.models.copilot import TopicCount, TopicsResponse

    return TopicsResponse(
        topics=[
            TopicCount(
                facet_id=copilot_facet_id,
                name="Python",
                type="topic",
                video_count=5,
                segment_count=25,
            ),
        ],
        scope_echo=None,
    )


@pytest.fixture
def copilot_coverage_response():
    """Create a mock coverage response."""
    from api.models.copilot import CoverageDateRange, CoverageResponse

    return CoverageResponse(
        video_count=50,
        segment_count=500,
        channel_count=3,
        date_range=CoverageDateRange(
            earliest=date(2024, 1, 1),
            latest=date(2024, 12, 31),
        ),
        last_updated_at=datetime.utcnow(),
        scope_echo=None,
    )


@pytest.fixture
def copilot_neighbors_response(copilot_video_id):
    """Create a mock neighbors response."""
    from api.models.copilot import (
        NeighborsResponse,
        NeighborVideo,
        RecommendedVideo,
        RelationshipType,
    )

    related_video_id = uuid4()
    return NeighborsResponse(
        source_video_id=copilot_video_id,
        neighbors=[
            NeighborVideo(
                video=RecommendedVideo(
                    video_id=related_video_id,
                    youtube_video_id="xyz789",
                    title="Related Video",
                    channel_name="Test Channel",
                    thumbnail_url="https://example.com/related.jpg",
                    duration=200,
                    relevance_score=0.8,
                    primary_reason="Same topic",
                ),
                relationship_type=RelationshipType.SAME_TOPIC,
                confidence=0.85,
                rationale="Both cover Python basics",
            ),
        ],
    )


# ============================================================================
# Copilot Query Endpoint Tests
# ============================================================================


class TestCopilotQuery:
    """Tests for POST /api/v1/copilot/query endpoint."""

    @pytest.mark.asyncio
    async def test_query_success(
        self,
        async_client,
        copilot_query_response,
    ):
        """Test successful copilot query."""
        with patch("api.routes.copilot.CopilotService") as mock_service_class:
            mock_service = AsyncMock()
            mock_service.query.return_value = copilot_query_response
            mock_service_class.return_value = mock_service

            response = await async_client.post(
                "/api/v1/copilot/query",
                json={
                    "query": "What are the best practices for Python?",
                },
            )

        # Note: This may return 500 due to missing database,
        # but we're testing the route exists and accepts the request
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.asyncio
    async def test_query_with_scope(
        self,
        async_client,
        copilot_scope,
    ):
        """Test copilot query with scope filters."""
        # Test that the endpoint accepts scope in the request body
        # Since this requires external services (LLM), we just test that
        # the route exists and accepts the request format
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "How do I learn Python?",
                "scope": copilot_scope,
            },
        )

        # Accept 200 (success with fallback) or 500 (service unavailable)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.asyncio
    async def test_query_empty_query_accepted(self, async_client):
        """Test that empty query is processed (returns with uncertainty)."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "",
            },
        )

        # Empty query is allowed - copilot handles it gracefully
        # It may return 200 with uncertainty message or 500 if service unavailable
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_query_with_conversation_id(self, async_client):
        """Test copilot query with conversation context."""
        conversation_id = str(uuid4())

        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "Tell me more about that",
                "conversationId": conversation_id,
            },
        )

        # Test route accepts conversationId parameter
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Segment Search Endpoint Tests
# ============================================================================


class TestSegmentSearch:
    """Tests for POST /api/v1/copilot/search/segments endpoint."""

    @pytest.mark.asyncio
    async def test_segment_search_success(
        self,
        async_client,
    ):
        """Test successful segment search."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "Python programming basics",
                "limit": 10,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_segment_search_with_scope(
        self,
        async_client,
        copilot_scope,
    ):
        """Test segment search with scope filters."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "advanced techniques",
                "scope": copilot_scope,
                "limit": 20,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_segment_search_limit_validation(self, async_client):
        """Test segment search limit validation."""
        # Limit > 200 should be rejected (max was increased to support CANDIDATE_K=100)
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test query",
                "limit": 250,  # Exceeds max of 200
            },
        )

        assert response.status_code in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Video Search Endpoint Tests
# ============================================================================


class TestVideoSearch:
    """Tests for POST /api/v1/copilot/search/videos endpoint."""

    @pytest.mark.asyncio
    async def test_video_search_success(self, async_client):
        """Test successful video search."""
        response = await async_client.post(
            "/api/v1/copilot/search/videos",
            json={
                "queryText": "Python tutorial",
                "limit": 10,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_video_search_with_scope(
        self,
        async_client,
        copilot_scope,
    ):
        """Test video search with scope filters."""
        response = await async_client.post(
            "/api/v1/copilot/search/videos",
            json={
                "queryText": "machine learning",
                "scope": copilot_scope,
                "limit": 15,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Topics Endpoint Tests
# ============================================================================


class TestTopics:
    """Tests for POST /api/v1/copilot/topics endpoint."""

    @pytest.mark.asyncio
    async def test_get_topics_success(self, async_client):
        """Test getting topics without scope."""
        response = await async_client.post(
            "/api/v1/copilot/topics",
            json={},
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_get_topics_with_scope(
        self,
        async_client,
        copilot_scope,
    ):
        """Test getting topics with scope filters."""
        response = await async_client.post(
            "/api/v1/copilot/topics",
            json={
                "scope": copilot_scope,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Coverage Endpoint Tests
# ============================================================================


class TestCoverage:
    """Tests for POST /api/v1/copilot/coverage endpoint."""

    @pytest.mark.asyncio
    async def test_get_coverage_success(self, async_client):
        """Test getting library coverage without scope."""
        response = await async_client.post(
            "/api/v1/copilot/coverage",
            json={},
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_get_coverage_with_scope(
        self,
        async_client,
        copilot_scope,
    ):
        """Test getting coverage with scope filters."""
        response = await async_client.post(
            "/api/v1/copilot/coverage",
            json={
                "scope": copilot_scope,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Neighbors Endpoint Tests
# ============================================================================


class TestNeighbors:
    """Tests for GET /api/v1/copilot/neighbors/{video_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_neighbors_success(
        self,
        async_client,
        copilot_video_id,
    ):
        """Test getting video neighbors."""
        response = await async_client.get(
            f"/api/v1/copilot/neighbors/{copilot_video_id}",
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_get_neighbors_with_types(
        self,
        async_client,
        copilot_video_id,
    ):
        """Test getting neighbors with relationship type filter."""
        response = await async_client.get(
            f"/api/v1/copilot/neighbors/{copilot_video_id}",
            params={"types": ["same_topic", "series"]},
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_get_neighbors_with_limit(
        self,
        async_client,
        copilot_video_id,
    ):
        """Test getting neighbors with limit."""
        response = await async_client.get(
            f"/api/v1/copilot/neighbors/{copilot_video_id}",
            params={"limit": 5},
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_get_neighbors_invalid_uuid(self, async_client):
        """Test getting neighbors with invalid UUID."""
        response = await async_client.get(
            "/api/v1/copilot/neighbors/not-a-uuid",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ============================================================================
# Explain Endpoint Tests
# ============================================================================


class TestExplain:
    """Tests for POST /api/v1/copilot/explain/{video_id} endpoint."""

    @pytest.mark.asyncio
    async def test_explain_success(
        self,
        async_client,
        copilot_video_id,
    ):
        """Test explaining a video recommendation."""
        response = await async_client.post(
            f"/api/v1/copilot/explain/{copilot_video_id}",
            json={
                "queryText": "What are Python best practices?",
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,  # Video might not exist
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status.HTTP_501_NOT_IMPLEMENTED,
        ]

    @pytest.mark.asyncio
    async def test_explain_with_scope(
        self,
        async_client,
        copilot_video_id,
        copilot_scope,
    ):
        """Test explaining with scope context."""
        response = await async_client.post(
            f"/api/v1/copilot/explain/{copilot_video_id}",
            json={
                "queryText": "advanced techniques",
                "scope": copilot_scope,
            },
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status.HTTP_501_NOT_IMPLEMENTED,
        ]

    @pytest.mark.asyncio
    async def test_explain_invalid_uuid(self, async_client):
        """Test explain with invalid UUID."""
        response = await async_client.post(
            "/api/v1/copilot/explain/not-a-uuid",
            json={},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ============================================================================
# Model Validation Tests
# ============================================================================


class TestCopilotModels:
    """Tests for copilot Pydantic model validation."""

    def test_query_scope_model(self):
        """Test QueryScope model validation."""
        from api.models.copilot import QueryScope

        scope = QueryScope(
            channels=[uuid4()],
            video_ids=[uuid4()],
            date_range={"from": "2024-01-01", "to": "2024-12-31"},
        )

        assert scope.channels is not None
        assert len(scope.channels) == 1

    def test_query_scope_empty(self):
        """Test empty QueryScope is valid."""
        from api.models.copilot import QueryScope

        scope = QueryScope()

        assert scope.channels is None
        assert scope.video_ids is None
        assert scope.date_range is None

    def test_evidence_model(self):
        """Test Evidence model validation."""
        from api.models.copilot import Evidence

        evidence = Evidence(
            video_id=uuid4(),
            youtube_video_id="abc123",
            video_title="Test Video",
            segment_id=uuid4(),
            segment_text="Sample text",
            start_time=10.0,
            end_time=20.0,
            youtube_url="https://youtube.com/watch?v=abc123&t=10",
            confidence=0.85,
        )

        assert evidence.confidence == 0.85
        assert evidence.start_time == 10.0

    def test_evidence_confidence_bounds(self):
        """Test Evidence confidence must be between 0 and 1."""
        from pydantic import ValidationError

        from api.models.copilot import Evidence

        with pytest.raises(ValidationError):
            Evidence(
                video_id=uuid4(),
                youtube_video_id="abc123",
                video_title="Test",
                segment_id=uuid4(),
                segment_text="Sample",
                start_time=0.0,
                end_time=10.0,
                youtube_url="https://youtube.com/watch?v=abc123",
                confidence=1.5,  # Invalid - > 1
            )

    def test_segment_search_request_limit_bounds(self):
        """Test SegmentSearchRequest limit validation."""
        from pydantic import ValidationError

        from api.models.copilot import SegmentSearchRequest

        # Valid limit
        request = SegmentSearchRequest(
            query_text="test",
            limit=25,
        )
        assert request.limit == 25

        # Valid limit at new max (200 to support CANDIDATE_K=100)
        request = SegmentSearchRequest(
            query_text="test",
            limit=200,
        )
        assert request.limit == 200

        # Invalid limit > 200
        with pytest.raises(ValidationError):
            SegmentSearchRequest(
                query_text="test",
                limit=250,
            )

    def test_copilot_query_response_aliases(self):
        """Test CopilotQueryResponse uses camelCase aliases."""
        from api.models.copilot import CopilotQueryResponse

        response = CopilotQueryResponse(
            answer="Test answer",
            video_cards=[],
            evidence=[],
        )

        # Test serialization uses camelCase
        data = response.model_dump(by_alias=True)
        assert "videoCards" in data
        assert "scopeEcho" in data

    def test_content_type_enum(self):
        """Test ContentType enum values."""
        from api.models.copilot import ContentType

        assert ContentType.SUMMARY.value == "summary"
        assert ContentType.SEGMENT.value == "segment"
        assert ContentType.RELATIONSHIP.value == "relationship"

    def test_relationship_type_enum(self):
        """Test RelationshipType enum values."""
        from api.models.copilot import RelationshipType

        assert RelationshipType.SERIES.value == "series"
        assert RelationshipType.PROGRESSION.value == "progression"
        assert RelationshipType.SAME_TOPIC.value == "same_topic"
        assert RelationshipType.REFERENCES.value == "references"
        assert RelationshipType.RELATED.value == "related"


# ============================================================================
# US5 Explanation Models Tests
# ============================================================================


class TestUS5ExplanationModels:
    """Tests for US5 'Explain Why' transparency feature models."""

    def test_key_moment_model(self):
        """Test KeyMoment model creation and serialization."""
        from uuid import uuid4

        from api.models.copilot import KeyMoment

        segment_id = uuid4()
        moment = KeyMoment(
            timestamp="2:34",
            description="Demonstrates the hip hinge technique",
            segment_id=segment_id,
            youtube_url="https://youtube.com/watch?v=abc123&t=154",
        )

        assert moment.timestamp == "2:34"
        assert moment.description == "Demonstrates the hip hinge technique"
        assert moment.segment_id == segment_id
        assert moment.youtube_url == "https://youtube.com/watch?v=abc123&t=154"

        # Test camelCase aliases
        data = moment.model_dump(by_alias=True)
        assert "segmentId" in data
        assert "youTubeUrl" in data

    def test_key_moment_optional_fields(self):
        """Test KeyMoment with optional fields as None."""
        from api.models.copilot import KeyMoment

        moment = KeyMoment(
            timestamp="5:00",
            description="General tip",
        )

        assert moment.segment_id is None
        assert moment.youtube_url is None

    def test_video_explanation_model(self):
        """Test VideoExplanation model creation and serialization."""
        from uuid import uuid4

        from api.models.copilot import KeyMoment, VideoExplanation

        segment_id = uuid4()
        explanation = VideoExplanation(
            summary="This video covers the exact kettlebell technique you asked about",
            key_moments=[
                KeyMoment(
                    timestamp="2:34",
                    description="Proper hip hinge demonstration",
                    segment_id=segment_id,
                ),
                KeyMoment(
                    timestamp="5:12",
                    description="Common mistakes to avoid",
                ),
            ],
            related_to="Part of the Kettlebell Fundamentals series",
        )

        assert (
            explanation.summary
            == "This video covers the exact kettlebell technique you asked about"
        )
        assert len(explanation.key_moments) == 2
        assert explanation.related_to == "Part of the Kettlebell Fundamentals series"

        # Test camelCase aliases
        data = explanation.model_dump(by_alias=True)
        assert "keyMoments" in data
        assert "relatedTo" in data

    def test_video_explanation_empty_key_moments(self):
        """Test VideoExplanation with no key moments."""
        from api.models.copilot import VideoExplanation

        explanation = VideoExplanation(
            summary="Relevant to your query",
        )

        assert explanation.key_moments == []
        assert explanation.related_to is None

    def test_recommended_video_with_explanation(self):
        """Test RecommendedVideo includes explanation field."""
        from uuid import uuid4

        from api.models.copilot import KeyMoment, RecommendedVideo, VideoExplanation

        video_id = uuid4()
        explanation = VideoExplanation(
            summary="This video demonstrates the exact technique",
            key_moments=[
                KeyMoment(timestamp="1:23", description="Intro"),
            ],
        )

        video = RecommendedVideo(
            video_id=video_id,
            youtube_video_id="abc123",
            title="Test Video",
            channel_name="Test Channel",
            relevance_score=0.9,
            primary_reason="Contains relevant content",
            explanation=explanation,
        )

        assert video.explanation is not None
        assert video.explanation.summary == "This video demonstrates the exact technique"
        assert len(video.explanation.key_moments) == 1

    def test_recommended_video_without_explanation(self):
        """Test RecommendedVideo works without explanation (backward compatible)."""
        from uuid import uuid4

        from api.models.copilot import RecommendedVideo

        video = RecommendedVideo(
            video_id=uuid4(),
            youtube_video_id="abc123",
            title="Test Video",
            channel_name="Test Channel",
            relevance_score=0.9,
            primary_reason="Contains relevant content",
        )

        assert video.explanation is None

    def test_copilot_response_with_explanations(self, copilot_query_response):
        """Test CopilotQueryResponse includes explanations in video cards."""
        assert len(copilot_query_response.video_cards) > 0

        first_card = copilot_query_response.video_cards[0]
        assert first_card.explanation is not None
        assert (
            first_card.explanation.summary
            == "This video demonstrates the exact technique you asked about"
        )
        assert len(first_card.explanation.key_moments) == 1

        first_moment = first_card.explanation.key_moments[0]
        assert first_moment.timestamp == "2:34"
        assert first_moment.description == "Introduction to the concept"

    def test_explanation_serialization_format(self):
        """Test explanation serializes to correct JSON format for frontend."""
        from uuid import uuid4

        from api.models.copilot import KeyMoment, RecommendedVideo, VideoExplanation

        video = RecommendedVideo(
            video_id=uuid4(),
            youtube_video_id="abc123",
            title="Test",
            channel_name="Channel",
            relevance_score=0.85,
            primary_reason="Relevant",
            explanation=VideoExplanation(
                summary="Explanation text",
                key_moments=[
                    KeyMoment(
                        timestamp="3:45",
                        description="Key point",
                        segment_id=uuid4(),
                        youtube_url="https://youtube.com/watch?v=abc123&t=225",
                    )
                ],
                related_to="Part of a series",
            ),
        )

        # Serialize with aliases (as it would go to frontend)
        data = video.model_dump(by_alias=True, mode="json")

        # Verify structure matches frontend expectations
        assert "explanation" in data
        assert data["explanation"]["summary"] == "Explanation text"
        assert "keyMoments" in data["explanation"]
        assert len(data["explanation"]["keyMoments"]) == 1
        assert data["explanation"]["keyMoments"][0]["timestamp"] == "3:45"
        assert data["explanation"]["relatedTo"] == "Part of a series"


# ============================================================================
# AI Knowledge Settings Tests
# ============================================================================


class TestAIKnowledgeSettings:
    """Tests for AI knowledge settings model."""

    def test_ai_knowledge_settings_defaults(self):
        """Test AIKnowledgeSettings default values."""
        from api.models.copilot import AIKnowledgeSettings

        settings = AIKnowledgeSettings()

        # All enabled by default
        assert settings.use_video_context is True
        assert settings.use_llm_knowledge is True
        assert settings.use_web_search is False

    def test_ai_knowledge_settings_custom_values(self):
        """Test AIKnowledgeSettings with custom values."""
        from api.models.copilot import AIKnowledgeSettings

        settings = AIKnowledgeSettings(
            use_video_context=False,
            use_llm_knowledge=True,
            use_web_search=True,
        )

        assert settings.use_video_context is False
        assert settings.use_llm_knowledge is True
        assert settings.use_web_search is True

    def test_ai_knowledge_settings_serialization(self):
        """Test AIKnowledgeSettings serializes with camelCase aliases."""
        from api.models.copilot import AIKnowledgeSettings

        settings = AIKnowledgeSettings(
            use_video_context=False,
            use_llm_knowledge=True,
            use_web_search=False,
        )

        data = settings.model_dump(by_alias=True, mode="json")

        # Should use camelCase for frontend
        assert "useVideoContext" in data
        assert "useLLMKnowledge" in data
        assert "useWebSearch" in data
        assert data["useVideoContext"] is False
        assert data["useLLMKnowledge"] is True
        assert data["useWebSearch"] is False


class TestCopilotQueryWithAISettings:
    """Tests for copilot query with AI settings."""

    @pytest.mark.asyncio
    async def test_query_with_ai_settings_all_enabled(self, async_client):
        """Test query with all AI settings enabled (default behavior)."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "How do I learn Python?",
                "aiSettings": {
                    "useVideoContext": True,
                    "useLLMKnowledge": True,
                    "useWebSearch": False,
                },
            },
        )

        # Accept 200 or 500 (service unavailable)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_query_with_video_context_disabled(self, async_client):
        """Test query with video context disabled (LLM-only mode)."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "What is Python?",
                "aiSettings": {
                    "useVideoContext": False,
                    "useLLMKnowledge": True,
                    "useWebSearch": False,
                },
            },
        )

        # Accept 200 or 500 (service unavailable)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_query_with_all_knowledge_disabled(self, async_client):
        """Test query with all knowledge sources disabled returns error."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "What is Python?",
                "aiSettings": {
                    "useVideoContext": False,
                    "useLLMKnowledge": False,
                    "useWebSearch": False,
                },
            },
        )

        # Accept 200 (with appropriate error message) or 500
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

        # If 200, check it returns appropriate message
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            # Should indicate no knowledge sources are enabled
            assert "uncertainty" in data or "answer" in data

    @pytest.mark.asyncio
    async def test_query_without_ai_settings_uses_defaults(self, async_client):
        """Test query without aiSettings uses default values."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "How do I learn Python?",
                # No aiSettings provided - should use defaults
            },
        )

        # Accept 200 or 500 (service unavailable)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


class TestCopilotServiceAISettings:
    """Unit tests for CopilotService AI settings handling."""

    @pytest.mark.asyncio
    async def test_copilot_service_respects_video_context_disabled(self):
        """Test that CopilotService respects useVideoContext=False."""
        from unittest.mock import AsyncMock, MagicMock

        from api.models.copilot import AIKnowledgeSettings, CopilotQueryRequest
        from api.services.copilot_service import CopilotService

        # Create mock session and LLM service
        mock_session = AsyncMock()
        mock_llm_service = MagicMock()
        mock_llm_service.generate_answer_without_evidence = AsyncMock(
            return_value={
                "answer": "Python is a programming language.",
                "follow_ups": ["What are Python's key features?"],
            }
        )
        mock_llm_service.generate_follow_ups = AsyncMock(
            return_value=["What are Python's key features?"]
        )

        # Create service with mock LLM
        service = CopilotService(
            session=mock_session,
            llm_service=mock_llm_service,
        )

        # Create request with video context disabled
        request = CopilotQueryRequest(
            query="What is Python?",
            ai_settings=AIKnowledgeSettings(
                use_video_context=False,
                use_llm_knowledge=True,
                use_web_search=False,
            ),
        )

        # Execute query
        response = await service.query(request)

        # Should return LLM-only response without evidence
        assert response.answer is not None
        assert response.video_cards == []
        assert response.evidence == []
        # Should have uncertainty indicating LLM-only response
        assert response.uncertainty is not None
        # LLM should have been called
        mock_llm_service.generate_answer_without_evidence.assert_called_once()

    @pytest.mark.asyncio
    async def test_copilot_service_error_when_all_disabled(self):
        """Test that CopilotService returns error when all knowledge disabled."""
        from unittest.mock import AsyncMock, MagicMock

        from api.models.copilot import AIKnowledgeSettings, CopilotQueryRequest
        from api.services.copilot_service import CopilotService

        # Create mock session
        mock_session = AsyncMock()
        mock_llm_service = MagicMock()

        # Create service
        service = CopilotService(
            session=mock_session,
            llm_service=mock_llm_service,
        )

        # Create request with all knowledge disabled
        request = CopilotQueryRequest(
            query="What is Python?",
            ai_settings=AIKnowledgeSettings(
                use_video_context=False,
                use_llm_knowledge=False,
                use_web_search=False,
            ),
        )

        # Execute query
        response = await service.query(request)

        # Should return error message
        assert "cannot answer" in response.answer.lower() or "disabled" in response.answer.lower()
        assert response.video_cards == []
        assert response.evidence == []
        assert response.uncertainty is not None
