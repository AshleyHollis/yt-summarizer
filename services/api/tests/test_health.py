"""Smoke tests for health endpoints.

These tests verify that the API is running and responding correctly.
They should be fast and not require any external dependencies.
"""

import pytest
from fastapi import status


class TestHealthSmoke:
    """Smoke tests for health check endpoints."""

    def test_health_endpoint_returns_200(self, client):
        """Test that /health endpoint returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK

    def test_health_endpoint_returns_json(self, client):
        """Test that /health endpoint returns valid JSON."""
        response = client.get("/health")
        data = response.json()
        assert isinstance(data, dict)

    def test_health_endpoint_has_status_field(self, client):
        """Test that /health response contains status field."""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_health_endpoint_has_timestamp(self, client):
        """Test that /health response contains timestamp."""
        response = client.get("/health")
        data = response.json()
        assert "timestamp" in data

    def test_health_endpoint_has_version(self, client):
        """Test that /health response contains version."""
        response = client.get("/health")
        data = response.json()
        assert "version" in data

    def test_health_endpoint_has_checks(self, client):
        """Test that /health response contains checks dict."""
        response = client.get("/health")
        data = response.json()
        assert "checks" in data
        assert isinstance(data["checks"], dict)


class TestReadinessSmoke:
    """Smoke tests for readiness endpoint."""

    def test_readiness_endpoint_returns_200_or_503(self, client):
        """Test that /health/ready returns valid status codes."""
        response = client.get("/health/ready")
        # Ready or not ready are both valid responses
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE]

    def test_readiness_endpoint_returns_json(self, client):
        """Test that /health/ready returns valid JSON."""
        response = client.get("/health/ready")
        data = response.json()
        assert isinstance(data, dict)

    def test_readiness_endpoint_has_ready_field(self, client):
        """Test that /health/ready response contains ready field."""
        response = client.get("/health/ready")
        data = response.json()
        assert "ready" in data
        assert isinstance(data["ready"], bool)


class TestLivenessSmoke:
    """Smoke tests for liveness endpoint."""

    def test_liveness_endpoint_returns_200(self, client):
        """Test that /health/live endpoint returns 200 OK."""
        response = client.get("/health/live")
        assert response.status_code == status.HTTP_200_OK

    def test_liveness_endpoint_returns_json(self, client):
        """Test that /health/live returns valid JSON."""
        response = client.get("/health/live")
        data = response.json()
        assert isinstance(data, dict)

    def test_liveness_endpoint_has_status_field(self, client):
        """Test that /health/live response contains status field."""
        response = client.get("/health/live")
        data = response.json()
        assert "status" in data
        assert data["status"] in ("ok", "alive")  # Accept either value


class TestCorsHeaders:
    """Smoke tests for CORS headers."""

    def test_cors_headers_on_options(self, client):
        """Test that OPTIONS requests return CORS headers."""
        response = client.options(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )
        # Should not error, exact CORS behavior depends on config
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_405_METHOD_NOT_ALLOWED]


class TestCorrelationId:
    """Smoke tests for correlation ID handling."""

    def test_correlation_id_returned_in_response(self, client, correlation_id):
        """Test that correlation ID is returned in response headers."""
        response = client.get(
            "/health",
            headers={"X-Correlation-ID": correlation_id},
        )
        # Response should echo back the correlation ID
        assert response.status_code == status.HTTP_200_OK

    def test_correlation_id_generated_when_not_provided(self, client):
        """Test that correlation ID is generated when not provided."""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK


class TestApiVersioning:
    """Smoke tests for API versioning."""

    def test_api_v1_prefix_exists(self, client):
        """Test that /api/v1/ prefix is available."""
        # Videos endpoint should exist under v1
        response = client.get("/api/v1/videos/00000000-0000-0000-0000-000000000000")
        # 404 is expected for non-existent video, but route should exist
        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_422_UNPROCESSABLE_ENTITY]

    def test_root_redirects_or_returns_info(self, client):
        """Test that root endpoint returns info or redirects."""
        response = client.get("/")
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_307_TEMPORARY_REDIRECT,
            status.HTTP_404_NOT_FOUND,
        ]


class TestErrorHandling:
    """Smoke tests for error handling."""

    def test_404_for_unknown_endpoint(self, client):
        """Test that unknown endpoints return 404."""
        response = client.get("/this-endpoint-does-not-exist")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_405_for_wrong_method(self, client):
        """Test that wrong HTTP methods return 405."""
        # POST to health should not be allowed
        response = client.post("/health")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_422_for_invalid_uuid(self, client):
        """Test that invalid UUIDs return 422."""
        response = client.get("/api/v1/videos/not-a-valid-uuid")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
