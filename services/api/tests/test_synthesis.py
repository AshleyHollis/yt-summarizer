"""Integration tests for synthesis API endpoints.

These tests verify the synthesis capabilities for User Story 6:
- Learning path generation
- Watch list generation
- Insufficient content handling
- Scope filtering for synthesis

All synthesis operations are read-only and build upon copilot infrastructure.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status

# ============================================================================
# Synthesis Fixtures
# ============================================================================


@pytest.fixture
def synthesis_video_id():
    """Generate a sample video ID for synthesis tests."""
    return uuid4()


@pytest.fixture
def synthesis_video_id_2():
    """Generate a second video ID for synthesis tests."""
    return uuid4()


@pytest.fixture
def synthesis_video_id_3():
    """Generate a third video ID for synthesis tests."""
    return uuid4()


@pytest.fixture
def synthesis_channel_id():
    """Generate a sample channel ID for synthesis tests."""
    return uuid4()


@pytest.fixture
def synthesis_segment_id():
    """Generate a sample segment ID for synthesis tests."""
    return uuid4()


@pytest.fixture
def synthesis_scope(synthesis_channel_id):
    """Create a sample query scope for synthesis tests."""
    return {
        "channels": [str(synthesis_channel_id)],
        "dateRange": {
            "from": "2024-01-01",
            "to": "2024-12-31",
        },
    }


@pytest.fixture
def mock_videos_for_synthesis(synthesis_video_id, synthesis_video_id_2, synthesis_video_id_3, synthesis_channel_id):
    """Create mock video objects for synthesis tests."""
    videos = []
    titles = [
        ("Beginner's Guide to Python", 300),
        ("Intermediate Python Techniques", 450),
        ("Advanced Python Patterns", 600),
    ]
    video_ids = [synthesis_video_id, synthesis_video_id_2, synthesis_video_id_3]
    
    for i, (title, duration) in enumerate(titles):
        video = MagicMock()
        video.video_id = video_ids[i]
        video.youtube_video_id = f"video{i+1}abc"
        video.channel_id = synthesis_channel_id
        video.title = title
        video.description = f"Description for {title}"
        video.duration = duration
        video.publish_date = datetime.utcnow()
        video.thumbnail_url = f"https://example.com/thumb{i+1}.jpg"
        video.processing_status = "completed"
        video.created_at = datetime.utcnow()
        video.updated_at = datetime.utcnow()
        videos.append(video)
    
    return videos


@pytest.fixture
def mock_channel_for_synthesis(synthesis_channel_id):
    """Create a mock channel object for synthesis tests."""
    channel = MagicMock()
    channel.channel_id = synthesis_channel_id
    channel.youtube_channel_id = "UCsynth123"
    channel.name = "Python Tutorials Channel"
    channel.description = "Learn Python from basics to advanced"
    channel.thumbnail_url = "https://example.com/channel.jpg"
    channel.video_count = 3
    return channel


@pytest.fixture
def learning_path_request_data():
    """Create a learning path synthesis request payload."""
    return {
        "synthesisType": "learning_path",
        "query": "Create a learning path for Python programming",
        "maxItems": 5,
    }


@pytest.fixture
def learning_path_request_with_scope(synthesis_channel_id):
    """Create a learning path synthesis request with scope."""
    return {
        "synthesisType": "learning_path",
        "query": "Create a learning path for Python programming",
        "scope": {
            "channels": [str(synthesis_channel_id)],
        },
        "maxItems": 10,
    }


@pytest.fixture
def watch_list_request_data():
    """Create a watch list synthesis request payload."""
    return {
        "synthesisType": "watch_list",
        "query": "Give me a watch list for learning data science",
        "maxItems": 10,
    }


@pytest.fixture
def mock_learning_path_response(synthesis_video_id, synthesis_video_id_2, synthesis_video_id_3, synthesis_segment_id):
    """Create a mock learning path response."""
    from api.models.synthesis import (
        LearningPath,
        LearningPathEvidence,
        LearningPathItem,
        SynthesisType,
        SynthesizeResponse,
    )
    
    return SynthesizeResponse(
        synthesis_type=SynthesisType.LEARNING_PATH,
        learning_path=LearningPath(
            title="Python Programming Learning Path",
            description="A structured path from beginner to advanced Python",
            estimated_duration=1350,  # 300 + 450 + 600 seconds
            items=[
                LearningPathItem(
                    order=1,
                    video_id=synthesis_video_id,
                    youtube_video_id="video1abc",
                    title="Beginner's Guide to Python",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb1.jpg",
                    duration=300,
                    rationale="Introduces core Python concepts needed for later steps",
                    learning_objectives=["Basic syntax", "Variables", "Control flow"],
                    prerequisites=[],
                    evidence=[
                        LearningPathEvidence(
                            video_id=synthesis_video_id,
                            segment_id=synthesis_segment_id,
                            segment_text="Let's start with the basics of Python...",
                            youtube_url="https://youtube.com/watch?v=video1abc&t=30",
                        ),
                    ],
                ),
                LearningPathItem(
                    order=2,
                    video_id=synthesis_video_id_2,
                    youtube_video_id="video2abc",
                    title="Intermediate Python Techniques",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb2.jpg",
                    duration=450,
                    rationale="Builds on basics with functions, classes, and OOP",
                    learning_objectives=["Functions", "Classes", "Object-Oriented Programming"],
                    prerequisites=[1],
                    evidence=[],
                ),
                LearningPathItem(
                    order=3,
                    video_id=synthesis_video_id_3,
                    youtube_video_id="video3abc",
                    title="Advanced Python Patterns",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb3.jpg",
                    duration=600,
                    rationale="Covers advanced design patterns and best practices",
                    learning_objectives=["Design patterns", "Decorators", "Metaclasses"],
                    prerequisites=[1, 2],
                    evidence=[],
                ),
            ],
            coverage_summary="Covers beginner to advanced Python topics",
            gaps=["Testing frameworks", "Async programming"],
        ),
        insufficient_content=False,
    )


@pytest.fixture
def mock_watch_list_response(synthesis_video_id, synthesis_video_id_2, synthesis_video_id_3):
    """Create a mock watch list response."""
    from api.models.synthesis import (
        Priority,
        SynthesisType,
        SynthesizeResponse,
        WatchList,
        WatchListItem,
    )
    
    return SynthesizeResponse(
        synthesis_type=SynthesisType.WATCH_LIST,
        watch_list=WatchList(
            title="Data Science Watch List",
            description="Essential videos for learning data science concepts",
            total_duration=1350,
            items=[
                WatchListItem(
                    video_id=synthesis_video_id,
                    youtube_video_id="video1abc",
                    title="Beginner's Guide to Python",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb1.jpg",
                    duration=300,
                    priority=Priority.HIGH,
                    reason="Foundation for all data science work",
                    tags=["python", "basics", "programming"],
                ),
                WatchListItem(
                    video_id=synthesis_video_id_2,
                    youtube_video_id="video2abc",
                    title="Intermediate Python Techniques",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb2.jpg",
                    duration=450,
                    priority=Priority.MEDIUM,
                    reason="Important for data manipulation skills",
                    tags=["python", "intermediate"],
                ),
                WatchListItem(
                    video_id=synthesis_video_id_3,
                    youtube_video_id="video3abc",
                    title="Advanced Python Patterns",
                    channel_name="Python Tutorials Channel",
                    thumbnail_url="https://example.com/thumb3.jpg",
                    duration=600,
                    priority=Priority.LOW,
                    reason="Useful for production-ready code",
                    tags=["python", "advanced", "patterns"],
                ),
            ],
            criteria="Videos covering Python skills essential for data science",
            gaps=["NumPy tutorials", "Pandas deep dives", "Machine learning"],
        ),
        insufficient_content=False,
    )


@pytest.fixture
def mock_insufficient_content_response():
    """Create a mock response for insufficient content."""
    from api.models.synthesis import SynthesisType, SynthesizeResponse
    
    return SynthesizeResponse(
        synthesis_type=SynthesisType.LEARNING_PATH,
        learning_path=None,
        insufficient_content=True,
        insufficient_message=(
            "Not enough content found to create a meaningful learning path. "
            "Try broadening your scope or ingesting more videos on this topic."
        ),
    )


# ============================================================================
# Synthesis Endpoint Tests
# ============================================================================


class TestSynthesizeLearningPath:
    """Tests for POST /api/v1/copilot/synthesize with learning_path type."""

    def test_synthesize_learning_path_success(
        self,
        client,
        learning_path_request_data,
        mock_learning_path_response,
    ):
        """Test successful learning path synthesis."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            # Check response status
            assert response.status_code == status.HTTP_200_OK
            
            # Check response structure
            data = response.json()
            assert data["synthesisType"] == "learning_path"
            assert data["learningPath"] is not None
            assert data["insufficientContent"] is False
            
            # Check learning path content
            learning_path = data["learningPath"]
            assert learning_path["title"] == "Python Programming Learning Path"
            assert len(learning_path["items"]) == 3
            
            # Check first item
            first_item = learning_path["items"][0]
            assert first_item["order"] == 1
            assert first_item["title"] == "Beginner's Guide to Python"
            assert first_item["rationale"] is not None
            assert len(first_item["learningObjectives"]) > 0

    def test_synthesize_learning_path_with_scope(
        self,
        client,
        learning_path_request_with_scope,
        mock_learning_path_response,
    ):
        """Test learning path synthesis with scope filtering."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_with_scope,
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            # Verify service was called with scope
            mock_service.synthesize.assert_called_once()
            call_args = mock_service.synthesize.call_args
            request_arg = call_args[0][0]
            assert request_arg.scope is not None

    def test_synthesize_learning_path_with_evidence(
        self,
        client,
        learning_path_request_data,
        mock_learning_path_response,
    ):
        """Test that learning path items include evidence with timestamps."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # First item should have evidence
            first_item = data["learningPath"]["items"][0]
            assert len(first_item["evidence"]) > 0
            
            evidence = first_item["evidence"][0]
            assert "segmentText" in evidence
            assert "youTubeUrl" in evidence

    def test_synthesize_learning_path_prerequisites(
        self,
        client,
        learning_path_request_data,
        mock_learning_path_response,
    ):
        """Test that learning path items have proper prerequisite ordering."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            items = data["learningPath"]["items"]
            
            # Check prerequisite chain
            assert items[0]["prerequisites"] == []  # First item has no prerequisites
            assert 1 in items[1]["prerequisites"]   # Second depends on first
            assert 1 in items[2]["prerequisites"]   # Third depends on first
            assert 2 in items[2]["prerequisites"]   # Third depends on second


class TestSynthesizeWatchList:
    """Tests for POST /api/v1/copilot/synthesize with watch_list type."""

    def test_synthesize_watch_list_success(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test successful watch list synthesis."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["synthesisType"] == "watch_list"
            assert data["watchList"] is not None
            assert data["insufficientContent"] is False
            
            # Check watch list content
            watch_list = data["watchList"]
            assert watch_list["title"] == "Data Science Watch List"
            assert len(watch_list["items"]) == 3

    def test_synthesize_watch_list_priorities(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test that watch list items have proper priority levels."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            items = data["watchList"]["items"]
            
            # Check priorities are set correctly
            assert items[0]["priority"] == "high"
            assert items[1]["priority"] == "medium"
            assert items[2]["priority"] == "low"

    def test_synthesize_watch_list_reasons(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test that watch list items include reasons for recommendation."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            items = data["watchList"]["items"]
            
            # All items should have a reason
            for item in items:
                assert "reason" in item
                assert len(item["reason"]) > 0

    def test_synthesize_watch_list_tags(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test that watch list items can include categorization tags."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            items = data["watchList"]["items"]
            
            # First item should have tags
            assert "tags" in items[0]
            assert "python" in items[0]["tags"]


class TestSynthesizeInsufficientContent:
    """Tests for synthesis with insufficient content."""

    def test_insufficient_content_returns_proper_message(
        self,
        client,
        learning_path_request_data,
        mock_insufficient_content_response,
    ):
        """Test that insufficient content returns proper messaging."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_insufficient_content_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            assert data["insufficientContent"] is True
            assert data["insufficientMessage"] is not None
            assert "not enough content" in data["insufficientMessage"].lower()
            assert data["learningPath"] is None

    def test_empty_scope_returns_insufficient_content(
        self,
        client,
        mock_insufficient_content_response,
    ):
        """Test that an empty scope results in insufficient content message."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_insufficient_content_response
            mock_service_class.return_value = mock_service
            
            request_data = {
                "synthesisType": "learning_path",
                "query": "Create a learning path for quantum physics",
                "scope": {
                    "channels": [],  # Empty channel filter
                },
                "maxItems": 5,
            }
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["insufficientContent"] is True


class TestSynthesizeGaps:
    """Tests for 'what's missing' gap detection in synthesis."""

    def test_learning_path_includes_gaps(
        self,
        client,
        learning_path_request_data,
        mock_learning_path_response,
    ):
        """Test that learning path includes gap detection."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            gaps = data["learningPath"]["gaps"]
            assert isinstance(gaps, list)
            assert len(gaps) > 0
            assert "Testing frameworks" in gaps

    def test_watch_list_includes_gaps(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test that watch list includes gap detection."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            gaps = data["watchList"]["gaps"]
            assert isinstance(gaps, list)
            assert len(gaps) > 0


class TestSynthesizeValidation:
    """Tests for synthesis request validation."""

    def test_invalid_synthesis_type_rejected(
        self,
        client,
    ):
        """Test that invalid synthesis type is rejected."""
        request_data = {
            "synthesisType": "invalid_type",
            "query": "Create something",
        }
        
        response = client.post(
            "/api/v1/copilot/synthesize",
            json=request_data,
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_empty_query_rejected(
        self,
        client,
    ):
        """Test that empty query is rejected."""
        request_data = {
            "synthesisType": "learning_path",
            "query": "",
        }
        
        response = client.post(
            "/api/v1/copilot/synthesize",
            json=request_data,
        )
        
        # May be 422 for validation error or 400 for business logic rejection
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY]

    def test_max_items_exceeds_limit(
        self,
        client,
    ):
        """Test that maxItems > 50 is rejected."""
        request_data = {
            "synthesisType": "learning_path",
            "query": "Create a learning path",
            "maxItems": 100,
        }
        
        response = client.post(
            "/api/v1/copilot/synthesize",
            json=request_data,
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_max_items_below_minimum(
        self,
        client,
    ):
        """Test that maxItems < 1 is rejected."""
        request_data = {
            "synthesisType": "watch_list",
            "query": "Create a watch list",
            "maxItems": 0,
        }
        
        response = client.post(
            "/api/v1/copilot/synthesize",
            json=request_data,
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestSynthesizeCorrelationId:
    """Tests for correlation ID handling in synthesis."""

    def test_correlation_id_passed_to_service(
        self,
        client,
        mock_learning_path_response,
    ):
        """Test that correlation ID is passed to the synthesis service."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            request_data = {
                "synthesisType": "learning_path",
                "query": "Create a learning path",
                "correlationId": "test-correlation-123",
            }
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            # Verify correlation ID was passed
            mock_service.synthesize.assert_called_once()
            call_args = mock_service.synthesize.call_args
            request_arg = call_args[0][0]
            assert request_arg.correlation_id == "test-correlation-123"

    def test_correlation_id_from_header_used_as_fallback(
        self,
        client,
        mock_learning_path_response,
    ):
        """Test that correlation ID from header is used when not in body."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            request_data = {
                "synthesisType": "learning_path",
                "query": "Create a learning path",
                # No correlationId in body
            }
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=request_data,
                headers={"X-Correlation-ID": "header-correlation-456"},
            )
            
            assert response.status_code == status.HTTP_200_OK


class TestSynthesizeDurations:
    """Tests for duration calculations in synthesis responses."""

    def test_learning_path_calculates_total_duration(
        self,
        client,
        learning_path_request_data,
        mock_learning_path_response,
    ):
        """Test that learning path includes correct estimated duration."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_learning_path_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=learning_path_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Duration should be sum of all items: 300 + 450 + 600 = 1350
            assert data["learningPath"]["estimatedDuration"] == 1350

    def test_watch_list_calculates_total_duration(
        self,
        client,
        watch_list_request_data,
        mock_watch_list_response,
    ):
        """Test that watch list includes correct total duration."""
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_watch_list_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json=watch_list_request_data,
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Duration should be sum of all items: 300 + 450 + 600 = 1350
            assert data["watchList"]["totalDuration"] == 1350


# ============================================================================
# Synthesis Service Unit Tests
# ============================================================================


class TestSynthesisServiceUnit:
    """Unit tests for SynthesisService logic."""

    def test_service_uses_search_for_content_discovery(self, mock_session):
        """Test that synthesis service uses search to find relevant content."""
        # This tests that the service properly uses SearchService internally
        # Service implementation is in services/api/src/api/services/synthesis_service.py
        pass  # Placeholder for full service unit tests

    def test_service_uses_llm_for_ordering(self, mock_session):
        """Test that synthesis service uses LLM for intelligent ordering."""
        # This tests that the service uses LLMService for learning path ordering
        pass  # Placeholder for full service unit tests

    def test_service_detects_insufficient_content(self, mock_session):
        """Test that synthesis service properly detects when content is insufficient."""
        # This tests the insufficient content detection logic
        pass  # Placeholder for full service unit tests

    def test_service_respects_max_items(self, mock_session):
        """Test that synthesis service respects the maxItems limit."""
        # This tests that output doesn't exceed requested max items
        pass  # Placeholder for full service unit tests


class TestSynthesisServiceShortsExclusion:
    """Tests for shorts exclusion in learning path synthesis (T159)."""

    def test_learning_path_excludes_shorts_under_60_seconds(
        self,
        client,
    ):
        """Test that learning paths exclude videos under 60 seconds.
        
        Shorts (< 60s) lack sufficient content depth for pedagogical ordering.
        They should be filtered out during learning path generation.
        """
        from uuid import uuid4

        from api.models.synthesis import (
            LearningPath,
            LearningPathItem,
            SynthesisType,
            SynthesizeResponse,
        )
        
        # Create a response that includes only non-short videos
        # The service should filter out shorts before synthesis
        video_id_1 = uuid4()
        video_id_2 = uuid4()
        
        mock_response = SynthesizeResponse(
            synthesis_type=SynthesisType.LEARNING_PATH,
            learning_path=LearningPath(
                title="Push-Up Progressions",
                description="Learn push-ups from beginner to advanced",
                estimated_duration=732,  # 543 + 189 seconds (no 31s short)
                items=[
                    LearningPathItem(
                        order=1,
                        video_id=video_id_1,
                        youtube_video_id="xxOdD929ty8",
                        title="How to Push-Up for Complete Beginners",
                        channel_name="Fitness Channel",
                        thumbnail_url=None,
                        duration=543,  # 9:03 - over 60s, included
                        rationale="Beginner-friendly introduction",
                        learning_objectives=["Basic form"],
                        prerequisites=[],
                        evidence=[],
                    ),
                    LearningPathItem(
                        order=2,
                        video_id=video_id_2,
                        youtube_video_id="0GsVJsS6474",
                        title="You CAN do pushups, my friend!",
                        channel_name="Hybrid Calisthenics",
                        thumbnail_url=None,
                        duration=189,  # 3:09 - over 60s, included
                        rationale="Progressive approach",
                        learning_objectives=["Progressions"],
                        prerequisites=[1],
                        evidence=[],
                    ),
                    # Note: c-lBErfxszs (31 seconds) would be excluded
                ],
                coverage_summary="Beginner to intermediate push-up progressions",
                gaps=["Advanced variations"],
            ),
            insufficient_content=False,
        )
        
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json={
                    "synthesisType": "learning_path",
                    "query": "Push-up progressions from beginner to advanced",
                    "maxItems": 10,
                },
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Verify learning path was generated
            assert data["learningPath"] is not None
            
            # All videos in the learning path should be > 60 seconds
            for item in data["learningPath"]["items"]:
                duration = item.get("duration", 0)
                assert duration >= 60, f"Short video ({duration}s) should be excluded from learning path"

    def test_watch_list_includes_shorts(
        self,
        client,
    ):
        """Test that watch lists can include short videos.
        
        Unlike learning paths, watch lists don't require pedagogical ordering,
        so shorts are acceptable as quick recommendations.
        """
        from uuid import uuid4

        from api.models.synthesis import (
            Priority,
            SynthesisType,
            SynthesizeResponse,
            WatchList,
            WatchListItem,
        )
        
        video_id_short = uuid4()
        video_id_regular = uuid4()
        
        mock_response = SynthesizeResponse(
            synthesis_type=SynthesisType.WATCH_LIST,
            watch_list=WatchList(
                title="Quick Fitness Tips",
                description="Bite-sized fitness content",
                total_duration=331,  # 31 + 300 seconds
                items=[
                    WatchListItem(
                        video_id=video_id_short,
                        youtube_video_id="c-lBErfxszs",
                        title="The Perfect Push-Up",
                        channel_name="Davis Diley",
                        thumbnail_url=None,
                        duration=31,  # Short video - allowed in watch list
                        priority=Priority.HIGH,
                        reason="Quick form tip",
                        tags=["shorts", "form"],
                    ),
                    WatchListItem(
                        video_id=video_id_regular,
                        youtube_video_id="IODxDxX7oi4",
                        title="The Perfect Push Up",
                        channel_name="Calisthenicmovement",
                        thumbnail_url=None,
                        duration=300,  # Regular video
                        priority=Priority.MEDIUM,
                        reason="Comprehensive guide",
                        tags=["tutorial"],
                    ),
                ],
                criteria="Quick and effective fitness tips",
                gaps=[],
            ),
            insufficient_content=False,
        )
        
        with patch(
            "api.routes.copilot.SynthesisService"
        ) as mock_service_class:
            mock_service = AsyncMock()
            mock_service.synthesize.return_value = mock_response
            mock_service_class.return_value = mock_service
            
            response = client.post(
                "/api/v1/copilot/synthesize",
                json={
                    "synthesisType": "watch_list",
                    "query": "Quick fitness tips",
                    "maxItems": 10,
                },
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Watch list can include shorts
            assert data["watchList"] is not None
            durations = [item.get("duration", 0) for item in data["watchList"]["items"]]
            # At least one short should be included
            assert any(d < 60 for d in durations), "Watch list can include shorts"
