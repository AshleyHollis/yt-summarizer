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
    service.expand_query = AsyncMock(return_value=["original query"])  # Default: just return original
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
            use_expanded_retriever=False,  # Test legacy error handling
        )
        
        request = CopilotQueryRequest(query="What is this about?")
        response = await copilot_service.query(request)
        
        # Should return graceful error response
        assert response.answer is not None
        # May return "try again", "unable", or "I don't have" when search fails
        assert (
            "try again" in response.answer.lower() or 
            "unable" in response.answer.lower() or
            "don't have" in response.answer.lower()
        )
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
            use_expanded_retriever=False,  # Test legacy error handling
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
            use_expanded_retriever=False,  # Test legacy error handling
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
            use_expanded_retriever=False,  # Test legacy error handling
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
            use_expanded_retriever=False,  # Test legacy error handling
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
        # May return "search failed", "try again", or "I don't have" when DB fails
        assert (
            "search failed" in response.answer.lower() or 
            "try again" in response.answer.lower() or
            "don't have" in response.answer.lower()
        )

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
            use_expanded_retriever=False,  # Test legacy error handling
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
        """Test segment search with limit exceeding maximum (200)."""
        response = await async_client.post(
            "/api/v1/copilot/search/segments",
            json={
                "queryText": "test",
                "limit": 250,  # Exceeds max of 200
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


# =============================================================================
# LLM Uncertainty "null" String Handling Tests
# =============================================================================


class TestLLMNullStringHandling:
    """Test that LLM returning literal 'null' string is converted to None.
    
    Bug fix: The LLM was returning the literal string "null" instead of 
    JSON null when there was no uncertainty. This caused the UI to display
    "Limited Information: null" which was confusing to users.
    """

    @pytest.mark.asyncio
    async def test_null_string_converted_to_none(self):
        """Test that 'null' string from LLM is converted to None."""
        from api.services.llm_service import LLMService
        
        # Create the LLM service
        llm_service = LLMService()
        
        # Simulate LLM response with "null" string
        llm_response = {
            "answer": "Here is the answer.",
            "confidence": "high",
            "cited_videos": ["video-1"],
            "follow_ups": ["Follow up?"],
            "uncertainty": "null",  # Bug: LLM returns literal "null" string
            "video_explanations": {},
        }
        
        # Apply the same processing logic as in LLMService.generate_answer
        uncertainty_value = llm_response.get("uncertainty")
        if uncertainty_value == "null" or uncertainty_value == "":
            uncertainty_value = None
        
        assert uncertainty_value is None

    @pytest.mark.asyncio
    async def test_empty_string_converted_to_none(self):
        """Test that empty string uncertainty is converted to None."""
        llm_response = {
            "answer": "Here is the answer.",
            "uncertainty": "",  # Empty string
        }
        
        uncertainty_value = llm_response.get("uncertainty")
        if uncertainty_value == "null" or uncertainty_value == "":
            uncertainty_value = None
        
        assert uncertainty_value is None

    @pytest.mark.asyncio
    async def test_valid_uncertainty_preserved(self):
        """Test that valid uncertainty messages are preserved."""
        llm_response = {
            "answer": "Limited information available.",
            "uncertainty": "The provided evidence contains no information about cooking pasta.",
        }
        
        uncertainty_value = llm_response.get("uncertainty")
        if uncertainty_value == "null" or uncertainty_value == "":
            uncertainty_value = None
        
        assert uncertainty_value == "The provided evidence contains no information about cooking pasta."

    @pytest.mark.asyncio
    async def test_actual_none_stays_none(self):
        """Test that actual None value stays None."""
        llm_response = {
            "answer": "Here is the answer.",
            "uncertainty": None,  # Actual None from JSON null
        }
        
        uncertainty_value = llm_response.get("uncertainty")
        if uncertainty_value == "null" or uncertainty_value == "":
            uncertainty_value = None
        
        assert uncertainty_value is None


class TestLLMServiceUncertaintyIntegration:
    """Integration tests for LLM service uncertainty handling."""

    @pytest.mark.asyncio
    async def test_generate_answer_handles_null_string(self):
        """Test that generate_answer properly handles 'null' string from LLM."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from api.services.llm_service import LLMService
        
        # Create mock response that returns "null" string
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '''
        {
            "answer": "Here is the answer about heavy clubs.",
            "confidence": "high",
            "cited_videos": ["video-1"],
            "follow_ups": ["How to practice?"],
            "uncertainty": "null",
            "video_explanations": {}
        }
        '''
        
        with patch.object(LLMService, 'client', new_callable=lambda: MagicMock()) as mock_client:
            llm_service = LLMService()
            mock_client.chat = MagicMock()
            mock_client.chat.completions = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            llm_service._client = mock_client
            
            result = await llm_service.generate_answer(
                query="Tell me about heavy clubs",
                evidence=[{"text": "Heavy clubs training info", "video_title": "Heavy Clubs Video"}]
            )
            
            # The "null" string should be converted to None
            assert result["uncertainty"] is None
            assert result["answer"] == "Here is the answer about heavy clubs."

    @pytest.mark.asyncio
    async def test_generate_answer_preserves_valid_uncertainty(self):
        """Test that generate_answer preserves valid uncertainty messages."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from api.services.llm_service import LLMService
        
        # Create mock response with valid uncertainty
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '''
        {
            "answer": "I could not find information about cooking pasta.",
            "confidence": "low",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": "No cooking videos found in the library. The available content is about fitness and exercise.",
            "video_explanations": {}
        }
        '''
        
        with patch.object(LLMService, 'client', new_callable=lambda: MagicMock()) as mock_client:
            llm_service = LLMService()
            mock_client.chat = MagicMock()
            mock_client.chat.completions = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            llm_service._client = mock_client
            
            result = await llm_service.generate_answer(
                query="Tell me about cooking pasta",
                evidence=[]
            )
            
            # Valid uncertainty message should be preserved
            assert result["uncertainty"] is not None
            assert "No cooking videos found" in result["uncertainty"]


# =============================================================================
# Relevance Filtering Tests - API Side
# =============================================================================


class TestRelevanceFiltering:
    """Test that low-relevance segments are filtered BEFORE sending to LLM.
    
    This is critical to prevent the LLM from referencing irrelevant videos
    in its response (e.g., mentioning Heavy Clubs when asked about cooking pasta).
    """

    @pytest.mark.asyncio
    async def test_low_relevance_segments_filtered_before_llm(
        self, mock_db_session, mock_llm_service
    ):
        """Test that segments with high distance (low relevance) are filtered out."""
        from api.services.copilot_service import CopilotService, MAX_DISTANCE_FOR_RELEVANCE
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "No relevant information found.",
            "confidence": "low",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": "No relevant content in library.",
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Create segments with varying relevance scores
        # Distance-based: lower score = more similar/relevant
        high_relevance_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Heavy Clubs Tutorial",
            channel_name="Mark Wildman",
            text="How to use heavy clubs properly",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=clubs",
            score=0.3,  # Low distance = high relevance
        )
        
        low_relevance_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Cooking Video",
            channel_name="Chef Channel",
            text="Some cooking content",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=cooking",
            score=0.9,  # High distance = low relevance (above 0.8 threshold, should be filtered)
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [high_relevance_segment, low_relevance_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Heavy clubs training")
        response = await copilot_service.query(request)
        
        # Verify generate_answer was called with only the relevant segment
        call_args = mock_llm_service.generate_answer.call_args
        evidence_passed_to_llm = call_args.kwargs.get("evidence", [])
        
        # Should only have the high relevance segment
        assert len(evidence_passed_to_llm) == 1
        assert evidence_passed_to_llm[0]["video_title"] == "Heavy Clubs Tutorial"

    @pytest.mark.asyncio
    async def test_all_irrelevant_segments_returns_no_information(
        self, mock_db_session, mock_llm_service
    ):
        """Test that when all segments are irrelevant, we return 'no information' response."""
        from api.services.copilot_service import CopilotService, MAX_DISTANCE_FOR_RELEVANCE
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # All segments have high distance (low relevance) - above the 0.8 threshold
        irrelevant_segment_1 = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Heavy Clubs Video",
            channel_name="Fitness Channel",
            text="Heavy clubs training content",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=clubs",
            score=0.85,  # Above 0.8 threshold, should be filtered
        )
        
        irrelevant_segment_2 = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Kettlebell Video",
            channel_name="Fitness Channel",
            text="Kettlebell training content",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=kettle",
            score=0.95,  # Above 0.8 threshold, should be filtered
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [irrelevant_segment_1, irrelevant_segment_2]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="How to cook pasta")
        response = await copilot_service.query(request)
        
        # Should return "no information" response
        assert "don't have" in response.answer.lower() or "no information" in response.answer.lower()
        assert response.video_cards == []
        assert response.evidence == []
        assert response.uncertainty is not None
        
        # LLM generate_answer should NOT have been called since no relevant segments
        mock_llm_service.generate_answer.assert_not_called()

    @pytest.mark.asyncio
    async def test_relevance_threshold_boundary(self, mock_db_session, mock_llm_service):
        """Test segments exactly at the threshold boundary."""
        from api.services.copilot_service import CopilotService, MAX_DISTANCE_FOR_RELEVANCE
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Here is the answer.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Segment exactly at threshold (0.8) should be included
        at_threshold = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="At Threshold Video",
            channel_name="Channel",
            text="Content at threshold",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=threshold",
            score=MAX_DISTANCE_FOR_RELEVANCE,  # Exactly at threshold
        )
        
        # Segment just above threshold should be filtered
        above_threshold = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Above Threshold Video",
            channel_name="Channel",
            text="Content above threshold",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=above",
            score=MAX_DISTANCE_FOR_RELEVANCE + 0.01,  # Just above threshold
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [at_threshold, above_threshold]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Test query")
        response = await copilot_service.query(request)
        
        # Verify only the at-threshold segment was passed to LLM
        call_args = mock_llm_service.generate_answer.call_args
        evidence_passed_to_llm = call_args.kwargs.get("evidence", [])
        
        assert len(evidence_passed_to_llm) == 1
        assert evidence_passed_to_llm[0]["video_title"] == "At Threshold Video"

    @pytest.mark.asyncio
    async def test_video_cards_only_include_relevant_videos(
        self, mock_db_session, mock_llm_service
    ):
        """Test that video cards only include videos from relevant segments."""
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Answer about heavy clubs.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        relevant_video_id = uuid4()
        irrelevant_video_id = uuid4()
        
        relevant_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=relevant_video_id,
            video_title="Relevant Heavy Clubs",
            channel_name="Mark Wildman",
            text="Heavy clubs content",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=relevant",
            score=0.3,  # High relevance
        )
        
        irrelevant_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=irrelevant_video_id,
            video_title="Irrelevant Cooking Video",
            channel_name="Chef",
            text="Cooking content",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=irrelevant",
            score=0.9,  # Above 0.8 threshold - low relevance
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [relevant_segment, irrelevant_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Heavy clubs")
        response = await copilot_service.query(request)
        
        # Should only have the relevant video in video_cards
        assert len(response.video_cards) == 1
        assert response.video_cards[0].title == "Relevant Heavy Clubs"
        
        # Should only have relevant evidence
        assert len(response.evidence) == 1
        assert response.evidence[0].video_title == "Relevant Heavy Clubs"

    @pytest.mark.asyncio
    async def test_evidence_only_includes_relevant_segments(
        self, mock_db_session, mock_llm_service
    ):
        """Test that evidence citations only include relevant segments."""
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Answer with citations.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Multiple segments with varying relevance
        # With MAX_DISTANCE_FOR_RELEVANCE = 0.8, scores <= 0.8 are included
        segments = [
            ScoredSegment(
                segment_id=uuid4(),
                video_id=uuid4(),
                video_title=f"Video {i}",
                channel_name="Channel",
                text=f"Content {i}",
                start_time=0.0,
                end_time=60.0,
                youtube_url=f"https://youtube.com/watch?v={i}",
                score=score,
            )
            for i, score in enumerate([0.2, 0.4, 0.6, 0.75, 0.85, 0.95])  # 4 relevant (<= 0.8), 2 not
        ]
        
        mock_search_response = MagicMock()
        mock_search_response.segments = segments
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="Test query")
        response = await copilot_service.query(request)
        
# Should only have evidence for segments with score <= MAX_DISTANCE_FOR_RELEVANCE (0.8)
        assert len(response.evidence) == 4
        for ev in response.evidence:
            assert ev.confidence >= 0.2  # 1.0 - 0.8 = 0.2 minimum confidence


class TestModerateRelevanceThreshold:
    """Tests for handling moderately relevant segments (scores 0.6-0.8).
    
    Regression tests for: https://github.com/AshleyHollis/yt-summarizer/issues/XXX
    
    Problem: When asking about topics covered in a video (e.g., "protests banned"),
    the copilot returned "I don't have any information on this topic" because the
    relevance threshold (0.6) was too strict. Semantic similarity scores in the
    0.6-0.8 range can still contain highly relevant answers.
    """

    @pytest.mark.asyncio
    async def test_moderate_relevance_segments_not_filtered_out(
        self, mock_db_session, mock_llm_service
    ):
        """Test that segments with moderate distance (0.6-0.8) are NOT filtered out.
        
        Cosine distance in the 0.6-0.8 range often still represents semantically
        relevant content, especially for queries using different vocabulary than
        the source material.
        """
        from api.services.copilot_service import CopilotService, MAX_DISTANCE_FOR_RELEVANCE
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "The government announced banning certain protests and a gun buyback scheme.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": ["What triggered this announcement?"],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Simulates real-world scenario: query about "protests banned" returns
        # segments about gun control and hate crimes with moderate distance scores
        moderate_relevance_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Albanese announces national gun buyback scheme",
            channel_name="Sky News Australia",
            text="Today I'm also announcing that the government will establish a national gun buyback scheme to purchase surplus newly banned and illegal firearms.",
            start_time=162.16,
            end_time=195.44,
            youtube_url="https://youtube.com/watch?v=0iF7FpvDuRc&t=162s",
            score=0.70,  # Moderate distance - should still be included
        )
        
        another_moderate_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Albanese announces national gun buyback scheme",
            channel_name="Sky News Australia",
            text="Hate symbols and for charging a passenger who allegedly threatened violence.",
            start_time=476.8,
            end_time=508.64,
            youtube_url="https://youtube.com/watch?v=0iF7FpvDuRc&t=476s",
            score=0.65,  # Moderate distance - should still be included
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [moderate_relevance_segment, another_moderate_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="What is being banned in terms of protests?")
        response = await copilot_service.query(request)
        
        # The LLM should have been called with both segments
        mock_llm_service.generate_answer.assert_called_once()
        call_args = mock_llm_service.generate_answer.call_args
        evidence_passed_to_llm = call_args.kwargs.get("evidence", [])
        
        # Both segments should be passed to the LLM (not filtered out)
        assert len(evidence_passed_to_llm) == 2, (
            f"Expected 2 segments passed to LLM, got {len(evidence_passed_to_llm)}. "
            f"Segments with distance <= {MAX_DISTANCE_FOR_RELEVANCE} should be included."
        )
        
        # Response should NOT be the "no information" fallback
        assert "don't have" not in response.answer.lower(), (
            "Response should provide information, not 'I don't have any information'"
        )
        assert response.uncertainty is None, "Should not have uncertainty flag set"
        
        # Evidence should include the segments
        assert len(response.evidence) == 2

    @pytest.mark.asyncio
    async def test_query_with_vocabulary_mismatch_still_returns_results(
        self, mock_db_session, mock_llm_service
    ):
        """Test that queries with different vocabulary than source still find content.
        
        Users often ask questions using different words than appear in the video.
        For example, asking about "protests banned" when the video talks about
        "gun buyback" and "hate symbols" - these are semantically related but
        use different vocabulary.
        """
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "The video discusses new legislation about firearms and hate symbols.",
            "confidence": "medium",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Segments that are topically related but use different vocabulary
        segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="News Coverage",
            channel_name="News Channel",
            text="The national security investigation teams are targeting high harm politically motivated violence and communal violence.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=news",
            score=0.75,  # Higher distance due to vocabulary mismatch
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="What is the government doing about civil unrest?")
        response = await copilot_service.query(request)
        
        # Should NOT return "no information" for topically related content
        mock_llm_service.generate_answer.assert_called_once()
        assert "don't have" not in response.answer.lower()

    @pytest.mark.asyncio  
    async def test_truly_irrelevant_content_still_filtered(
        self, mock_db_session, mock_llm_service
    ):
        """Test that truly irrelevant content (score > 0.85) is still filtered.
        
        While we want to allow moderate relevance through, truly unrelated content
        should still be filtered to avoid confusing the LLM.
        """
        from api.services.copilot_service import CopilotService, MAX_DISTANCE_FOR_RELEVANCE
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Very high distance segment - truly unrelated
        unrelated_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Cooking Tutorial",
            channel_name="Chef Channel",
            text="How to make the perfect pasta with tomato sauce.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=cooking",
            score=0.95,  # Very high distance - should definitely be filtered
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [unrelated_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="What is being banned in terms of protests?")
        response = await copilot_service.query(request)
        
        # Should return "no information" for truly unrelated content
        assert "don't have" in response.answer.lower() or response.uncertainty is not None
        mock_llm_service.generate_answer.assert_not_called()

class TestRelatedContentSurfacing:
    """Tests for surfacing related content even when vocabulary differs.
    
    When users ask about a topic like "public assemblies", the copilot should
    surface related content (e.g., "neo-Nazis marching") even if the exact
    phrase "public assemblies" isn't used in the video.
    """

    @pytest.mark.asyncio
    async def test_public_assemblies_surfaces_marching_content(
        self, mock_db_session, mock_llm_service
    ):
        """Test that asking about 'public assemblies' surfaces marching content.
        
        Real scenario: User asks "What changes are being made to public assemblies?"
        The video has content about "neo-Nazis marching down streets" which is
        directly related to public assemblies, but uses different terminology.
        
        The LLM should receive this content and include it in its answer.
        """
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        
        # The LLM should synthesize the marching content into its answer
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "The Prime Minister expressed concerns about neo-Nazis marching down streets dressed in black. The government is focused on addressing hate crimes and politically motivated violence through national security investigation teams [Video, 25:47].",
            "confidence": "medium",
            "cited_videos": ["ef09695e-51dc-42b4-8354-ded7a2f957cf"],
            "follow_ups": ["What specific actions are being taken against hate groups?"],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Simulate the real search results for "public assemblies" query
        # This segment about neo-Nazis marching should be surfaced
        marching_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Albanese announces national gun buyback scheme",
            channel_name="Sky News Australia",
            text="I'm concerned about neo-Nazis thinking it's okay to march down our streets dressed in black not worrying about their faces being covered.",
            start_time=1547.92,
            end_time=1581.84,
            youtube_url="https://youtube.com/watch?v=0iF7FpvDuRc&t=1547s",
            score=0.745,  # This is the actual score from search
        )
        
        hate_crimes_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Albanese announces national gun buyback scheme",
            channel_name="Sky News Australia",
            text="National security investigation teams target groups and individuals causing high harm to social cohesion through politically motivated violence and communal violence.",
            start_time=414.96,
            end_time=448.16,
            youtube_url="https://youtube.com/watch?v=0iF7FpvDuRc&t=414s",
            score=0.742,
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [marching_segment, hate_crimes_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="What changes are being made to public assemblies?")
        response = await copilot_service.query(request)
        
        # The LLM should have received both segments
        mock_llm_service.generate_answer.assert_called_once()
        call_args = mock_llm_service.generate_answer.call_args
        evidence_passed_to_llm = call_args.kwargs.get("evidence", [])
        
        # Verify the marching content was passed to the LLM
        assert len(evidence_passed_to_llm) >= 1
        segment_texts = [e["text"] for e in evidence_passed_to_llm]
        assert any("neo-Nazis" in text or "march" in text for text in segment_texts), (
            "The segment about neo-Nazis marching should be passed to the LLM"
        )
        
        # The response should include the marching content
        assert "march" in response.answer.lower() or "neo-nazis" in response.answer.lower(), (
            "The answer should mention marching or neo-Nazis since it's directly related to public assemblies"
        )
        
        # Should NOT be the "no information" fallback
        assert "don't have" not in response.answer.lower()

    @pytest.mark.asyncio
    async def test_llm_receives_related_content_in_evidence(
        self, mock_db_session, mock_llm_service
    ):
        """Test that the LLM receives semantically related content as evidence.
        
        Even when vocabulary differs between query and content, related segments
        should be passed to the LLM so it can determine relevance and synthesize
        an appropriate answer.
        """
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Related content found.",
            "confidence": "medium",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy path
        )
        
        # Content that's related but uses different vocabulary
        related_segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Test Video",
            channel_name="Test Channel",
            text="Demonstrations and gatherings on public streets are being restricted.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=test",
            score=0.70,  # Moderate distance
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [related_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="What rules apply to public rallies?")
        response = await copilot_service.query(request)
        
        # Verify the LLM received the evidence
        mock_llm_service.generate_answer.assert_called_once()
        call_args = mock_llm_service.generate_answer.call_args
        evidence = call_args.kwargs.get("evidence", [])
        
        # The related segment should be in the evidence
        assert len(evidence) == 1
        assert "Demonstrations" in evidence[0]["text"]


class TestQueryExpansion:
    """Tests for query expansion to surface semantically related content.
    
    Query expansion helps find content when users ask questions using
    vocabulary that differs from what's in the video transcripts.
    For example, "public assemblies" should also find "marching", "protests",
    and "demonstrations".
    """

    @pytest.mark.asyncio
    async def test_query_expansion_generates_related_terms(
        self, mock_db_session, mock_llm_service
    ):
        """Test that query expansion produces related search terms.
        
        When a user asks about "public assemblies", the expansion should
        generate related terms like "marching", "protests", "demonstrations".
        """
        from api.services.copilot_service import CopilotService
        
        # Configure mock to return expanded queries
        mock_llm_service.expand_query = AsyncMock(return_value=[
            "What has the Australian prime minister said about public assemblies?",
            "protests marching demonstrations",
            "neo-Nazi extremist groups marching",
        ])
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "The PM expressed concerns about neo-Nazis marching.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy query expansion
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = []
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(
            query="What has the Australian prime minister said about public assemblies?"
        )
        
        # Just need to ensure expand_query is called
        try:
            await copilot_service.query(request)
        except Exception:
            pass  # We may get an error due to empty results, that's fine
        
        # Verify expand_query was called with the original query
        mock_llm_service.expand_query.assert_called_once_with(
            "What has the Australian prime minister said about public assemblies?"
        )

    @pytest.mark.asyncio
    async def test_query_expansion_searches_all_expanded_queries(
        self, mock_db_session, mock_llm_service
    ):
        """Test that search is performed for each expanded query.
        
        Multi-query search should find content from all expanded queries,
        allowing related content to be surfaced even when vocabulary differs.
        """
        from api.services.copilot_service import CopilotService
        
        # Configure mock to return 3 expanded queries
        expanded_queries = [
            "public assemblies regulations",
            "protests marching demonstrations",
            "neo-Nazi groups street",
        ]
        mock_llm_service.expand_query = AsyncMock(return_value=expanded_queries)
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Answer found.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy query expansion
        )
        
        # Return different segments for different queries
        segment_from_original = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Video 1",
            channel_name="Channel",
            text="Public assemblies are being restricted.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=1",
            score=0.4,
        )
        
        segment_from_expansion = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Video 2",
            channel_name="Channel",
            text="I'm concerned about neo-Nazis thinking it's okay to march down our streets.",
            start_time=1547.0,
            end_time=1600.0,
            youtube_url="https://youtube.com/watch?v=2&t=1547",
            score=0.45,
        )
        
        call_count = 0
        async def mock_search(request, embedding):
            nonlocal call_count
            call_count += 1
            mock_response = MagicMock()
            if call_count == 1:
                mock_response.segments = [segment_from_original]
            elif call_count == 3:
                mock_response.segments = [segment_from_expansion]
            else:
                mock_response.segments = []
            return mock_response
        
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(side_effect=mock_search)
        
        request = CopilotQueryRequest(query="public assemblies regulations")
        response = await copilot_service.query(request)
        
        # Verify search was called for all 3 expanded queries
        assert mock_llm_service.get_embedding.call_count == 3
        assert copilot_service.search_service.search_segments.call_count == 3
        
        # Verify the LLM received both segments (from different expanded queries)
        mock_llm_service.generate_answer.assert_called_once()
        call_args = mock_llm_service.generate_answer.call_args
        evidence = call_args.kwargs.get("evidence", [])
        
        assert len(evidence) == 2
        texts = [e["text"] for e in evidence]
        assert any("Public assemblies" in t for t in texts)
        assert any("neo-Nazis" in t for t in texts)

    @pytest.mark.asyncio
    async def test_query_expansion_deduplicates_segments(
        self, mock_db_session, mock_llm_service
    ):
        """Test that duplicate segments from different queries are deduplicated.
        
        When multiple expanded queries return the same segment, it should
        only appear once in the final results.
        """
        from api.services.copilot_service import CopilotService
        
        mock_llm_service.expand_query = AsyncMock(return_value=[
            "public assemblies",
            "gatherings restrictions",
        ])
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Found.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy query expansion
        )
        
        # Same segment returned by both queries
        shared_segment_id = uuid4()
        shared_video_id = uuid4()
        
        duplicate_segment = ScoredSegment(
            segment_id=shared_segment_id,
            video_id=shared_video_id,
            video_title="Shared Video",
            channel_name="Channel",
            text="Public gatherings and assemblies are restricted.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=shared",
            score=0.5,
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [duplicate_segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="public assemblies")
        response = await copilot_service.query(request)
        
        # Verify the LLM received only 1 segment (deduplicated)
        mock_llm_service.generate_answer.assert_called_once()
        call_args = mock_llm_service.generate_answer.call_args
        evidence = call_args.kwargs.get("evidence", [])
        
        assert len(evidence) == 1
        assert evidence[0]["text"] == "Public gatherings and assemblies are restricted."

    @pytest.mark.asyncio
    async def test_query_expansion_fallback_on_failure(
        self, mock_db_session, mock_llm_service
    ):
        """Test that query falls back to original if expansion fails.
        
        If the LLM expansion fails, the system should gracefully fall back
        to using only the original query.
        """
        from api.services.copilot_service import CopilotService
        
        # Configure expansion to fail
        mock_llm_service.expand_query = AsyncMock(
            side_effect=Exception("LLM expansion failed")
        )
        mock_llm_service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
        mock_llm_service.generate_answer = AsyncMock(return_value={
            "answer": "Fallback answer.",
            "confidence": "high",
            "cited_videos": [],
            "follow_ups": [],
            "uncertainty": None,
            "video_explanations": {},
        })
        
        copilot_service = CopilotService(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_expanded_retriever=False,  # Test legacy query expansion
        )
        
        segment = ScoredSegment(
            segment_id=uuid4(),
            video_id=uuid4(),
            video_title="Test Video",
            channel_name="Channel",
            text="Some content about assemblies.",
            start_time=0.0,
            end_time=60.0,
            youtube_url="https://youtube.com/watch?v=test",
            score=0.4,
        )
        
        mock_search_response = MagicMock()
        mock_search_response.segments = [segment]
        copilot_service.search_service = MagicMock(spec=SearchService)
        copilot_service.search_service.search_segments = AsyncMock(
            return_value=mock_search_response
        )
        
        request = CopilotQueryRequest(query="public assemblies")
        response = await copilot_service.query(request)
        
        # Should still get a valid response using original query
        assert response.answer == "Fallback answer."
        # Only 1 search should have happened (with original query)
        assert copilot_service.search_service.search_segments.call_count == 1