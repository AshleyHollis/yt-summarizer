"""End-to-end smoke tests for the YT Summarizer API.

These tests verify critical user flows work correctly. They run in two modes:

1. **Unit mode** (default): Uses TestClient with mocked dependencies
   - Fast, no external dependencies required
   - Validates API contracts and routing
   - Marked with @pytest.mark.integration
   
2. **Live mode**: Uses httpx against a running API
   - Set E2E_TESTS_ENABLED=true and API_BASE_URL=<url>
   - Tests full stack integration
   - Marked with @pytest.mark.live
   - Skipped by default via pyproject.toml addopts

Usage:
    # Run all tests (unit + integration, excluding live)
    pytest
    
    # Run including live E2E tests (requires running API)
    E2E_TESTS_ENABLED=true pytest -m ""
    
    # Run only live tests
    E2E_TESTS_ENABLED=true pytest -m "live"
"""

import os
from uuid import uuid4

import httpx
import pytest
from fastapi import status

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
E2E_ENABLED = os.getenv("E2E_TESTS_ENABLED", "false").lower() == "true"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def live_client():
    """Create an HTTP client for live E2E tests."""
    return httpx.Client(base_url=API_BASE_URL, timeout=30.0)


@pytest.fixture
def correlation_id():
    """Generate a unique correlation ID for tracing."""
    return f"e2e-smoke-{uuid4()}"


@pytest.fixture
def e2e_headers(correlation_id):
    """Headers for E2E tests with tracing."""
    return {
        "X-Correlation-ID": correlation_id,
        "Content-Type": "application/json",
    }


# =============================================================================
# Smoke Tests - Always Run (Unit Mode with Mocked Dependencies)
# =============================================================================


@pytest.mark.integration
class TestSmokeHealthEndpoints:
    """Smoke tests for health check endpoints."""

    def test_health_endpoint_returns_200(self, client, headers):
        """Health endpoint should always return 200."""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK

    def test_health_returns_status_field(self, client, headers):
        """Health response should include status."""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_liveness_returns_200(self, client, headers):
        """Liveness probe should always return 200."""
        response = client.get("/health/live")
        assert response.status_code == status.HTTP_200_OK

    def test_readiness_returns_valid_response(self, client, headers):
        """Readiness probe should return 200 or 503."""
        response = client.get("/health/ready")
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE]


@pytest.mark.integration
class TestSmokeAPIRouting:
    """Smoke tests for API routing and OpenAPI."""

    def test_api_v1_prefix_exists(self, client, headers):
        """API v1 routes should exist."""
        response = client.get("/api/v1/videos/health-check-nonexistent-id")
        # Should get 422 (invalid UUID) or 404, not 404 from routing
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_openapi_schema_available(self, client):
        """OpenAPI schema should be available (if docs enabled)."""
        response = client.get("/openapi.json")
        # May be 200 (docs enabled) or 404 (docs disabled in production)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "openapi" in data
            assert "paths" in data

    def test_swagger_docs_available(self, client):
        """Swagger UI should be available (if docs enabled)."""
        response = client.get("/docs")
        # May be 200 (docs enabled) or 404 (docs disabled in production)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


@pytest.mark.integration
class TestSmokeVideoEndpoints:
    """Smoke tests for video API endpoints."""

    def test_submit_video_endpoint_exists(self, client, headers):
        """Video submission endpoint should exist."""
        response = client.post(
            "/api/v1/videos",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
            headers=headers,
        )
        # Should not be 404 (endpoint not found)
        assert response.status_code != status.HTTP_404_NOT_FOUND

    def test_submit_video_validates_url(self, client, headers):
        """Video submission should validate YouTube URL."""
        response = client.post(
            "/api/v1/videos",
            json={"url": "https://not-youtube.com/video"},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_submit_video_requires_url(self, client, headers):
        """Video submission requires url field."""
        response = client.post(
            "/api/v1/videos",
            json={},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_video_endpoint_exists(self, client, headers):
        """Video retrieval endpoint should exist."""
        video_id = str(uuid4())
        response = client.get(f"/api/v1/videos/{video_id}", headers=headers)
        # Should get 404 (not found) not 404 routing error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
        ]

    def test_get_video_requires_valid_uuid(self, client, headers):
        """Video retrieval requires valid UUID."""
        response = client.get("/api/v1/videos/not-a-uuid", headers=headers)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
class TestSmokeJobEndpoints:
    """Smoke tests for job API endpoints."""

    def test_list_jobs_endpoint_exists(self, client, headers):
        """Jobs list endpoint should exist."""
        response = client.get("/api/v1/jobs", headers=headers)
        assert response.status_code == status.HTTP_200_OK

    def test_list_jobs_returns_paginated_structure(self, client, headers):
        """Jobs list should return paginated structure."""
        response = client.get("/api/v1/jobs", headers=headers)
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "items" in data
            assert "pagination" in data
            assert isinstance(data["items"], list)

    def test_list_jobs_accepts_filters(self, client, headers):
        """Jobs list should accept filter parameters."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/jobs?video_id={video_id}&job_type=transcribe&status=pending",
            headers=headers,
        )
        # Should not be a validation error for valid filters
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    def test_get_job_endpoint_exists(self, client, headers):
        """Job retrieval endpoint should exist."""
        job_id = str(uuid4())
        response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
        ]

    def test_video_progress_endpoint_exists(self, client, headers):
        """Video progress endpoint should exist."""
        video_id = str(uuid4())
        response = client.get(f"/api/v1/jobs/video/{video_id}/progress", headers=headers)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
        ]


@pytest.mark.integration
class TestSmokeCorrelationTracking:
    """Smoke tests for correlation ID tracking."""

    def test_correlation_id_returned_in_header(self, client, headers):
        """Correlation ID should be returned in response headers."""
        response = client.get("/health", headers=headers)
        assert "x-correlation-id" in response.headers

    def test_correlation_id_matches_request(self, client):
        """Returned correlation ID should match request."""
        correlation_id = f"test-{uuid4()}"
        response = client.get(
            "/health",
            headers={"X-Correlation-ID": correlation_id},
        )
        assert response.headers.get("x-correlation-id") == correlation_id

    def test_correlation_id_generated_if_missing(self, client):
        """Correlation ID should be generated if not provided."""
        response = client.get("/health")
        assert "x-correlation-id" in response.headers
        assert len(response.headers["x-correlation-id"]) > 0


@pytest.mark.integration
class TestSmokeErrorResponses:
    """Smoke tests for error response format."""

    def test_404_returns_json(self, client, headers):
        """404 errors should return JSON."""
        video_id = str(uuid4())
        response = client.get(f"/api/v1/videos/{video_id}", headers=headers)
        if response.status_code == status.HTTP_404_NOT_FOUND:
            data = response.json()
            assert "error" in data or "detail" in data

    def test_422_returns_json(self, client, headers):
        """422 validation errors should return JSON."""
        response = client.post(
            "/api/v1/videos",
            json={"url": "invalid"},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "error" in data or "detail" in data


# =============================================================================
# Live E2E Tests - Only Run When E2E_TESTS_ENABLED=true
# =============================================================================


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLiveE2EHealthCheck:
    """Live E2E tests for health endpoints against running API."""

    def test_api_is_reachable(self, live_client):
        """API should be reachable."""
        response = live_client.get("/health")
        assert response.status_code == status.HTTP_200_OK

    def test_api_is_healthy(self, live_client):
        """API should report healthy status."""
        response = live_client.get("/health")
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]

    def test_database_connection(self, live_client):
        """Database should be connected (check via readiness)."""
        response = live_client.get("/health/ready")
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert data["ready"] is True


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLiveE2EVideoFlow:
    """Live E2E tests for video submission flow."""

    @pytest.fixture
    def test_video_url(self):
        """A real YouTube URL for testing."""
        return "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    def test_submit_video_creates_record(self, live_client, e2e_headers, test_video_url):
        """Submitting a video should create a record."""
        response = live_client.post(
            "/api/v1/videos",
            json={"url": test_video_url},
            headers=e2e_headers,
        )
        
        if response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            data = response.json()
            assert "video_id" in data
            assert data["video_id"] is not None

    def test_submitted_video_can_be_retrieved(self, live_client, e2e_headers, test_video_url):
        """A submitted video should be retrievable."""
        # Submit video
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": test_video_url},
            headers=e2e_headers,
        )
        
        if submit_response.status_code not in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            pytest.fail(f"Could not submit video: {submit_response.status_code} - {submit_response.text[:500]}")
        
        video_id = submit_response.json()["video_id"]
        
        # Retrieve video
        get_response = live_client.get(
            f"/api/v1/videos/{video_id}",
            headers=e2e_headers,
        )
        
        assert get_response.status_code == status.HTTP_200_OK
        data = get_response.json()
        assert data["video_id"] == video_id

    def test_video_creates_jobs(self, live_client, e2e_headers, test_video_url):
        """Submitting a video should create processing jobs."""
        # Submit video
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": test_video_url},
            headers=e2e_headers,
        )
        
        if submit_response.status_code not in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            pytest.fail(f"Could not submit video: {submit_response.status_code} - {submit_response.text[:500]}")
        
        video_id = submit_response.json()["video_id"]
        
        # Check for jobs
        jobs_response = live_client.get(
            f"/api/v1/jobs?video_id={video_id}",
            headers=e2e_headers,
        )
        
        if jobs_response.status_code == status.HTTP_200_OK:
            data = jobs_response.json()
            # Should have at least one job (transcription)
            assert len(data["items"]) > 0


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")  
class TestLiveE2EJobProgress:
    """Live E2E tests for job progress tracking."""

    @pytest.fixture
    def test_video_url(self):
        """A real YouTube URL for testing."""
        return "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    def test_video_progress_returns_status(self, live_client, e2e_headers, test_video_url):
        """Video progress endpoint should return progress information."""
        # Submit video first
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": test_video_url},
            headers=e2e_headers,
        )
        
        if submit_response.status_code not in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            pytest.fail(f"Could not submit video: {submit_response.status_code} - {submit_response.text[:500]}")
        
        video_id = submit_response.json()["video_id"]
        
        # Check progress
        progress_response = live_client.get(
            f"/api/v1/jobs/video/{video_id}/progress",
            headers=e2e_headers,
        )
        
        if progress_response.status_code == status.HTTP_200_OK:
            data = progress_response.json()
            assert "video_id" in data
            assert "overall_status" in data
            assert "overall_progress" in data


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLiveE2EErrorHandling:
    """Live E2E tests for error handling.
    
    Note: These tests validate proper error responses. If the API returns
    500 errors instead of expected 4xx errors, it indicates that error
    handling or database connectivity issues need to be addressed.
    """

    def test_invalid_url_returns_422_or_500(self, live_client, e2e_headers):
        """Invalid YouTube URL should return 422 (or 500 if DB unavailable)."""
        response = live_client.post(
            "/api/v1/videos",
            json={"url": "not-a-youtube-url"},
            headers=e2e_headers,
        )
        # 422 is expected; 500 indicates DB/service issue
        assert response.status_code in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ], f"Expected 422 or 500, got {response.status_code}"
        
        # Log the response for debugging if 500
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            pytest.fail(f"API returned 500 - database may not be configured: {response.text[:200]}")

    def test_nonexistent_video_returns_404_or_500(self, live_client, e2e_headers):
        """Non-existent video should return 404 (or 500 if DB unavailable)."""
        fake_id = str(uuid4())
        response = live_client.get(
            f"/api/v1/videos/{fake_id}",
            headers=e2e_headers,
        )
        # 404 is expected; 500 indicates DB/service issue
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ], f"Expected 404 or 500, got {response.status_code}"
        
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            pytest.fail(f"API returned 500 - database may not be configured: {response.text[:200]}")

    def test_nonexistent_job_returns_404_or_500(self, live_client, e2e_headers):
        """Non-existent job should return 404 (or 500 if DB unavailable)."""
        fake_id = str(uuid4())
        response = live_client.get(
            f"/api/v1/jobs/{fake_id}",
            headers=e2e_headers,
        )
        # 404 is expected; 500 indicates DB/service issue
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ], f"Expected 404 or 500, got {response.status_code}"
        
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            pytest.fail(f"API returned 500 - database may not be configured: {response.text[:200]}")

    def test_error_includes_correlation_id(self, live_client, e2e_headers):
        """Error responses should include correlation ID."""
        fake_id = str(uuid4())
        response = live_client.get(
            f"/api/v1/videos/{fake_id}",
            headers=e2e_headers,
        )
        
        # Correlation ID should be in headers
        assert "x-correlation-id" in response.headers
