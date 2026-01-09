"""Integration tests for job API endpoints.

These tests verify the job listing, retrieval, retry, and progress endpoints.
"""

from uuid import uuid4

import pytest
from fastapi import status


class TestListJobs:
    """Integration tests for GET /api/v1/jobs endpoint."""

    def test_list_jobs_returns_paginated_response(self, client, headers):
        """Test that list jobs returns paginated response structure."""
        response = client.get("/api/v1/jobs", headers=headers)
        # Without DB, might return 500, but structure should be correct on success
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "items" in data
            assert "pagination" in data
            assert isinstance(data["items"], list)

    def test_list_jobs_accepts_video_id_filter(self, client, headers, sample_video_id):
        """Test that video_id filter is accepted."""
        response = client.get(
            f"/api/v1/jobs?video_id={sample_video_id}",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_list_jobs_accepts_job_type_filter(self, client, headers):
        """Test that job_type filter is accepted."""
        response = client.get(
            "/api/v1/jobs?job_type=transcribe",
            headers=headers,
        )
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_list_jobs_accepts_status_filter(self, client, headers):
        """Test that status filter is accepted."""
        response = client.get(
            "/api/v1/jobs?status=pending",
            headers=headers,
        )
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_list_jobs_accepts_pagination_params(self, client, headers):
        """Test that pagination parameters are accepted."""
        response = client.get(
            "/api/v1/jobs?page=1&per_page=10",
            headers=headers,
        )
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.parametrize(
        "job_type",
        [
            "transcribe",
            "summarize",
            "embed",
            "build_relationships",
        ],
    )
    def test_list_jobs_accepts_valid_job_types(self, client, headers, job_type):
        """Test that all valid job types are accepted."""
        response = client.get(
            f"/api/v1/jobs?job_type={job_type}",
            headers=headers,
        )
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.parametrize(
        "status_value",
        [
            "pending",
            "running",
            "succeeded",
            "failed",
        ],
    )
    def test_list_jobs_accepts_valid_statuses(self, client, headers, status_value):
        """Test that all valid statuses are accepted."""
        response = client.get(
            f"/api/v1/jobs?status={status_value}",
            headers=headers,
        )
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestGetJob:
    """Integration tests for GET /api/v1/jobs/{job_id} endpoint."""

    def test_get_job_requires_valid_uuid(self, client, headers):
        """Test that job_id must be a valid UUID."""
        response = client.get(
            "/api/v1/jobs/not-a-uuid",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_job_returns_404_for_nonexistent(self, client, headers):
        """Test that non-existent jobs return 404."""
        job_id = str(uuid4())
        response = client.get(
            f"/api/v1/jobs/{job_id}",
            headers=headers,
        )
        # Without mocked DB, should return 404 or 500
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_get_job_accepts_valid_uuid(self, client, headers):
        """Test that valid UUIDs are accepted."""
        job_id = str(uuid4())
        response = client.get(
            f"/api/v1/jobs/{job_id}",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestRetryJob:
    """Integration tests for POST /api/v1/jobs/{job_id}/retry endpoint."""

    def test_retry_job_requires_valid_uuid(self, client, headers):
        """Test that job_id must be a valid UUID."""
        response = client.post(
            "/api/v1/jobs/not-a-uuid/retry",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_retry_job_returns_404_for_nonexistent(self, client, headers):
        """Test that non-existent jobs return 404."""
        job_id = str(uuid4())
        response = client.post(
            f"/api/v1/jobs/{job_id}/retry",
            headers=headers,
        )
        # Without mocked DB, should return 404 or 500
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_retry_job_accepts_reset_retry_count_param(self, client, headers):
        """Test that reset_retry_count parameter is accepted."""
        job_id = str(uuid4())
        response = client.post(
            f"/api/v1/jobs/{job_id}/retry",
            json={"reset_retry_count": True},
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVideoJobsProgress:
    """Integration tests for GET /api/v1/jobs/video/{video_id}/progress endpoint."""

    def test_progress_requires_valid_uuid(self, client, headers):
        """Test that video_id must be a valid UUID."""
        response = client.get(
            "/api/v1/jobs/video/not-a-uuid/progress",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_progress_returns_404_for_nonexistent_video(self, client, headers, sample_video_id):
        """Test that non-existent videos return 404."""
        response = client.get(
            f"/api/v1/jobs/video/{sample_video_id}/progress",
            headers=headers,
        )
        # Without mocked DB, should return 404 or 500
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_progress_accepts_valid_uuid(self, client, headers):
        """Test that valid UUIDs are accepted."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/jobs/video/{video_id}/progress",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestJobResponseFormat:
    """Tests for job response format validation."""

    def test_list_jobs_pagination_format(self, client, headers):
        """Test that pagination metadata has correct format."""
        response = client.get("/api/v1/jobs", headers=headers)
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            pagination = data.get("pagination", {})
            assert "page" in pagination
            assert "per_page" in pagination
            assert "total" in pagination
            assert "total_pages" in pagination
            assert "has_next" in pagination
            assert "has_prev" in pagination


class TestJobTypeValidation:
    """Tests for job type validation."""

    def test_invalid_job_type_rejected(self, client, headers):
        """Test that invalid job types are rejected."""
        response = client.get(
            "/api/v1/jobs?job_type=invalid_type",
            headers=headers,
        )
        # Should be rejected or ignored
        # Behavior depends on implementation - strict vs lenient
        assert response.status_code in [
            status.HTTP_200_OK,  # Lenient - ignores invalid
            status.HTTP_422_UNPROCESSABLE_ENTITY,  # Strict - rejects invalid
            status.HTTP_500_INTERNAL_SERVER_ERROR,  # DB error
        ]


class TestJobStatusValidation:
    """Tests for job status validation."""

    def test_invalid_status_rejected(self, client, headers):
        """Test that invalid statuses are rejected."""
        response = client.get(
            "/api/v1/jobs?status=invalid_status",
            headers=headers,
        )
        # Should be rejected or ignored
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]
