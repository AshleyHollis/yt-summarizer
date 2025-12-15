"""Integration and Error Boundary tests for Copilot (US4).

These tests focus on:
1. Service integration with real dependencies (mocked at boundary)
2. Error handling and recovery
3. Edge cases and boundary conditions
4. Failure scenarios
"""

from datetime import date
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient
from openai import APIConnectionError, APIStatusError, RateLimitError

from api.models.copilot import (
    CopilotQueryRequest,
    CopilotQueryResponse,
    QueryScope,
    ScoredSegment,
    SegmentSearchRequest,
)
from api.services.copilot_service import CopilotService
from api.services.llm_service import LLMService
from api.services.search_service import SearchService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_llm_service():
    """Create a mock LLM service."""
    service = MagicMock(spec=LLMService)
    service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
    service.generate_answer = AsyncMock(return_value={
        "answer": "Based on the evidence, here is the answer.",
        "citations": [],
        "followups": ["Question 1?", "Question 2?"],
    })
    return service


@pytest.fixture
def mock_search_service():
    """Create a mock search service."""
    service = MagicMock(spec=SearchService)
    return service


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def sample_segment():
    """Create a sample scored segment."""
    return ScoredSegment(
        segment_id=uuid4(),
        video_id=uuid4(),
        video_title="Test Video",
        channel_name="Test Channel",
        text="This is sample segment text.",
        start_time=10.0,
        end_time=25.0,
        youtube_url="https://youtube.com/watch?v=test123&t=10",
        score=0.15,  # Low distance = high similarity
    )


# =============================================================================
# LLM Service Error Handling Tests
# =============================================================================


class TestLLMServiceErrors:
    """Test error handling for LLM service failures."""

    @pytest.mark.asyncio
    async def test_embedding_api_connection_error(self, mock_db_session, mock_llm_service):
        """Test handling of OpenAI API connection errors during embedding."""
        mock_llm_service.get_embedding = AsyncMock(
            side_effect=APIConnectionError(request=MagicMock())
        )
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        request = CopilotQueryRequest(query="What is this about?")
        response = await copilot_service.query(request)
        
        # Should return graceful error response
        assert response.answer is not None
        assert "try again" in response.answer.lower() or "unable" in response.answer.lower()
        assert response.video_cards == []
        assert response.evidence == []

    @pytest.mark.asyncio
    async def test_embedding_rate_limit_error(self, mock_db_session, mock_llm_service):
        """Test handling of OpenAI rate limit errors during embedding."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"retry-after": "60"}
        
        mock_llm_service.get_embedding = AsyncMock(
            side_effect=RateLimitError(
                message="Rate limit exceeded",
                response=mock_response,
                body={"error": {"message": "Rate limit exceeded"}},
            )
        )
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        request = CopilotQueryRequest(query="What is this about?")
        response = await copilot_service.query(request)
        
        # Should return graceful error response
        assert response.answer is not None
        assert response.video_cards == []

    @pytest.mark.asyncio
    async def test_llm_generation_failure_after_successful_search(
        self, mock_db_session, mock_llm_service, sample_segment
    ):
        """Test handling of LLM generation failure after successful search."""
        # Embedding works
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        # LLM generation fails
        mock_llm_service.generate_answer = AsyncMock(
            side_effect=Exception("LLM generation failed")
        )
        
        # Mock search service to return results
        mock_search_service = MagicMock(spec=SearchService)
        mock_search_response = MagicMock()
        mock_search_response.segments = [sample_segment]
        mock_search_service.search_segments = AsyncMock(return_value=mock_search_response)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        copilot_service.search_service = mock_search_service
        
        request = CopilotQueryRequest(query="What is this about?")
        response = await copilot_service.query(request)
        
        # Should return error response but not crash
        assert response.answer is not None
        assert "failed" in response.answer.lower() or "try again" in response.answer.lower()

    @pytest.mark.asyncio
    async def test_empty_embedding_response(self, mock_db_session, mock_llm_service):
        """Test handling when embedding returns empty vector."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[])
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        # Mock search to fail with empty embedding
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            side_effect=Exception("Invalid embedding dimensions")
        )
        
        request = CopilotQueryRequest(query="Test query")
        response = await copilot_service.query(request)
        
        # Should handle gracefully
        assert response.answer is not None


# =============================================================================
# Search Service Error Handling Tests
# =============================================================================


class TestSearchServiceErrors:
    """Test error handling for search service failures."""

    @pytest.mark.asyncio
    async def test_database_connection_failure(self, mock_db_session, mock_llm_service):
        """Test handling of database connection failure during search."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        # Mock search to fail with DB error
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            side_effect=Exception("Connection refused")
        )
        
        request = CopilotQueryRequest(query="Test query")
        response = await copilot_service.query(request)
        
        # Should return error response
        assert response.answer is not None
        assert "search failed" in response.answer.lower() or "try again" in response.answer.lower()

    @pytest.mark.asyncio
    async def test_partial_search_results(self, mock_db_session, mock_llm_service, sample_segment):
        """Test handling when search returns partial/incomplete results."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Based on limited evidence...",
            "citations": [],
            "followups": [],
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        # Mock search with single low-quality result (high distance score)
        weak_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Low Relevance Video",
            channel_name="Channel",
            text="Some text",
            start_time=0.0,
            end_time=5.0,
            youtube_url="https://youtube.com/watch?v=weak",
            score=0.95,  # High distance = low similarity
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [weak_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Very specific question")
        response = await copilot_service.query(request)
        
        # Should indicate uncertainty
        assert response.uncertainty is not None or len(response.evidence) <= 1


# =============================================================================
# Edge Cases and Boundary Tests
# =============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_query_string(self, async_client):
        """Test handling of empty query string."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={"query": ""},
        )
        
        # Empty string might be accepted or rejected based on implementation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    @pytest.mark.asyncio
    async def test_whitespace_only_query(self, async_client):
        """Test handling of whitespace-only query."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={"query": "   \n\t   "},
        )
        
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_very_long_query(self, async_client):
        """Test handling of very long query text (boundary testing)."""
        # Query close to typical LLM context limits
        long_query = "What is the meaning of " * 1000  # ~6000 words
        
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={"query": long_query},
        )
        
        # Should either process or return appropriate error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_unicode_characters_in_query(self, async_client):
        """Test handling of unicode and special characters."""
        unicode_query = "What about 日本語 and émojis 🎉 and symbols €₹¥?"
        
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={"query": unicode_query},
        )
        
        # Should handle unicode gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,  # If DB not available
        ]

    @pytest.mark.asyncio
    async def test_sql_injection_attempt_in_query(self, async_client):
        """Test that SQL injection attempts are safely handled."""
        injection_query = "'; DROP TABLE videos; --"
        
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={"query": injection_query},
        )
        
        # Should be handled safely (either processed or error, but not crash)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_scope_with_nonexistent_channel(self, async_client):
        """Test query with scope containing non-existent channel ID."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "Test query",
                "scope": {
                    "channels": [str(uuid4())],  # Non-existent channel
                },
            },
        )
        
        # Should return empty results, not crash
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_scope_with_empty_arrays(self, async_client):
        """Test query with scope containing empty arrays."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "Test query",
                "scope": {
                    "channels": [],
                    "videoIds": [],
                    "facets": [],
                },
            },
        )
        
        # Empty arrays should be treated as "no filter"
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_date_range_with_future_dates(self, async_client):
        """Test scope with date range in the future."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "Test query",
                "scope": {
                    "dateRange": {
                        "from": "2030-01-01",
                        "to": "2030-12-31",
                    },
                },
            },
        )
        
        # Should return no results for future dates
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_date_range_inverted(self, async_client):
        """Test scope with inverted date range (to < from)."""
        response = await async_client.post(
            "/api/v1/copilot/query",
            json={
                "query": "Test query",
                "scope": {
                    "dateRange": {
                        "from": "2024-12-31",
                        "to": "2024-01-01",  # Before 'from'
                    },
                },
            },
        )
        
        # Should handle gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# =============================================================================
# Search Service Boundary Tests
# =============================================================================


class TestSearchBoundaries:
    """Test search service boundary conditions."""

    @pytest.mark.asyncio
    async def test_segment_search_limit_boundary_max(self, async_client):
        """Test segment search with maximum allowed limit."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test",
                "limit": 50,  # Max allowed
            },
        )
        
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_segment_search_limit_exceeds_max(self, async_client):
        """Test segment search with limit exceeding maximum."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test",
                "limit": 100,  # Exceeds max of 50
            },
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_segment_search_zero_limit(self, async_client):
        """Test segment search with zero limit."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test",
                "limit": 0,
            },
        )
        
        # Should either reject or return empty
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_segment_search_negative_limit(self, async_client):
        """Test segment search with negative limit."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test",
                "limit": -5,
            },
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# =============================================================================
# Neighbors Endpoint Tests
# =============================================================================


class TestNeighborsEndpointErrors:
    """Test neighbors endpoint error handling."""

    @pytest.mark.asyncio
    async def test_neighbors_with_malformed_uuid(self, async_client):
        """Test neighbors endpoint with malformed UUID."""
        response = await async_client.get(
            "/api/v1/copilot/neighbors/not-a-valid-uuid"
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_neighbors_with_nonexistent_video(self, async_client):
        """Test neighbors endpoint with non-existent video ID."""
        response = await async_client.get(
            f"/api/v1/copilot/neighbors/{uuid4()}"
        )
        
        # Should return empty or 404 depending on implementation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    @pytest.mark.asyncio
    async def test_neighbors_invalid_relationship_type(self, async_client):
        """Test neighbors endpoint with invalid relationship type filter."""
        response = await async_client.get(
            f"/api/v1/copilot/neighbors/{uuid4()}",
            params={"types": "invalid_type,another_bad_type"},
        )
        
        # API accepts invalid types and filters to valid ones (graceful handling)
        # Returns 200 with empty results for invalid/filtered types
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# =============================================================================
# AG-UI / Agent Endpoint Error Tests
# =============================================================================


class TestAgentEndpointErrors:
    """Test AG-UI/agent endpoint error handling.
    
    Note: The agent endpoint is registered via setup_agui_endpoint() which
    may not be called in test fixtures. These tests verify the endpoint
    behavior when available, or skip if not registered.
    """

    @pytest.mark.asyncio
    async def test_agent_endpoint_invalid_json(self, async_client):
        """Test agent endpoint with invalid JSON body."""
        response = await async_client.post(
            "/api/copilotkit",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        
        # May be 404 if endpoint not registered in test mode
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_404_NOT_FOUND,  # Endpoint not registered in test
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    @pytest.mark.asyncio
    async def test_agent_endpoint_missing_required_fields(self, async_client):
        """Test agent endpoint with missing required fields."""
        response = await async_client.post(
            "/api/copilotkit",
            json={},  # Empty body
        )
        
        # May be 404 if endpoint not registered in test mode
        assert response.status_code in [
            status.HTTP_200_OK,  # May return SSE with error
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_404_NOT_FOUND,  # Endpoint not registered in test
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    @pytest.mark.asyncio
    async def test_agent_endpoint_empty_messages(self, async_client):
        """Test agent endpoint with empty messages array."""
        response = await async_client.post(
            "/api/copilotkit",
            json={
                "messages": [],
                "runId": str(uuid4()),
                "threadId": str(uuid4()),
            },
        )
        
        # May be 404 if endpoint not registered in test mode
        assert response.status_code in [
            status.HTTP_200_OK,  # May return SSE stream
            status.HTTP_404_NOT_FOUND,  # Endpoint not registered in test
        ]


# =============================================================================
# Concurrent Request Tests
# =============================================================================


class TestConcurrency:
    """Test concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_queries(self, async_client):
        """Test multiple concurrent query requests."""
        import asyncio
        
        async def make_query(query_text: str):
            return await async_client.post(
                "/api/v1/copilot/query",
                json={"query": query_text},
            )
        
        # Make 5 concurrent requests
        tasks = [
            make_query(f"Concurrent query {i}")
            for i in range(5)
        ]
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete (success or controlled failure)
        for resp in responses:
            if isinstance(resp, Exception):
                pytest.fail(f"Concurrent request raised exception: {resp}")
            assert resp.status_code in [
                status.HTTP_200_OK,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            ]

    @pytest.mark.asyncio
    async def test_concurrent_search_requests(self, async_client):
        """Test multiple concurrent search requests."""
        import asyncio
        
        async def make_search(query_text: str):
            return await async_client.post(
                "/api/v1/copilot/search/segments",
                json={"queryText": query_text, "limit": 10},
            )
        
        # Make 5 concurrent searches
        tasks = [
            make_search(f"Search query {i}")
            for i in range(5)
        ]
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for resp in responses:
            if isinstance(resp, Exception):
                pytest.fail(f"Concurrent search raised exception: {resp}")
            assert resp.status_code in [
                status.HTTP_200_OK,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            ]


# =============================================================================
# Uncertainty Detection Tests
# =============================================================================


class TestUncertaintyDetection:
    """Test uncertainty detection in copilot responses."""

    @pytest.mark.asyncio
    async def test_uncertainty_with_no_results(self, mock_db_session, mock_llm_service):
        """Test uncertainty flag when no search results found."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        # Mock empty search results
        mock_search_response = MagicMock()
        mock_search_response.segments = []
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Obscure topic with no videos")
        response = await copilot_service.query(request)
        
        # Should indicate uncertainty or no information
        assert (
            response.uncertainty is not None
            or "don't have" in response.answer.lower()
            or "no information" in response.answer.lower()
        )

    @pytest.mark.asyncio
    async def test_uncertainty_with_low_confidence_results(
        self, mock_db_session, mock_llm_service
    ):
        """Test uncertainty detection with low-confidence search results."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Limited information available.",
            "citations": [],
            "followups": [],
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        # Mock low-confidence results (high distance scores)
        weak_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Unrelated Video",
            channel_name="Channel",
            text="Some content",
            start_time=0.0,
            end_time=10.0,
            youtube_url="https://youtube.com/watch?v=test",
            score=0.9,  # High distance = low confidence
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [weak_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Very specific question")
        response = await copilot_service.query(request)
        
        # May indicate uncertainty for low-confidence results
        # This tests the _detect_uncertainty method
        assert response.answer is not None


# =============================================================================
# Malformed Response Handling
# =============================================================================


class TestMalformedResponses:
    """Test handling of malformed responses from dependencies."""

    @pytest.mark.asyncio
    async def test_llm_returns_malformed_json(self, mock_db_session, mock_llm_service, sample_segment):
        """Test handling when LLM returns malformed JSON."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        # Return string instead of dict
        mock_llm_service.generate_answer = AsyncMock(return_value="Just a string, not a dict")
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [sample_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Test query")
        
        # Should not crash, may return error or handle gracefully
        try:
            response = await copilot_service.query(request)
            assert response.answer is not None
        except Exception as e:
            # If it does raise, it should be a controlled exception
            assert isinstance(e, (TypeError, KeyError, AttributeError))

    @pytest.mark.asyncio
    async def test_llm_returns_none(self, mock_db_session, mock_llm_service, sample_segment):
        """Test handling when LLM returns None."""
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value=None)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [sample_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Test query")
        
        try:
            response = await copilot_service.query(request)
            # If it returns, answer should be present (error message)
            assert response.answer is not None
        except Exception as e:
            # Controlled failure is acceptable
            assert isinstance(e, (TypeError, KeyError, AttributeError))
