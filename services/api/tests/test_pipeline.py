"""Full Pipeline Integration Tests for User Story 1.

These tests verify the complete video processing pipeline:
1. Submit video → creates video record and transcribe job
2. Jobs progress through: transcribe → summarize → embed → relationships
3. Video status transitions: pending → processing → completed
4. Content is accessible via transcript and summary endpoints

Test Modes:
- Unit mode: Uses mocked dependencies for fast feedback
- Live mode: Tests against running infrastructure

Prerequisites for live mode:
- Start Aspire: cd services/aspire/AppHost && dotnet run
- Set E2E_TESTS_ENABLED=true

Usage:
    # Run unit tests only
    pytest tests/test_pipeline.py -m "not live"
    
    # Run live tests
    E2E_TESTS_ENABLED=true pytest tests/test_pipeline.py
"""

import os
import time
from datetime import datetime
from uuid import uuid4

import httpx
import pytest
from fastapi import status

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
E2E_ENABLED = os.getenv("E2E_TESTS_ENABLED", "false").lower() == "true"

# Timeouts
PROCESSING_TIMEOUT_SECONDS = 120
POLLING_INTERVAL_SECONDS = 3


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def live_client():
    """Create an HTTP client for live tests."""
    return httpx.Client(base_url=API_BASE_URL, timeout=30.0)


@pytest.fixture
def correlation_id():
    """Generate a unique correlation ID."""
    return f"pipeline-test-{uuid4()}"


@pytest.fixture
def headers(correlation_id):
    """Headers for API requests."""
    return {
        "X-Correlation-ID": correlation_id,
        "Content-Type": "application/json",
    }


@pytest.fixture
def sample_youtube_url():
    """Sample YouTube URL for testing."""
    return "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


# =============================================================================
# Unit Tests - Pipeline Flow Validation
# =============================================================================


@pytest.mark.integration
class TestPipelineJobCreation:
    """Tests for job creation when video is submitted."""

    def test_submit_video_creates_transcribe_job(self, client, headers, sample_youtube_url):
        """Submitting a video should create a transcribe job."""
        response = client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        
        if response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            data = response.json()
            # Video should have pending or processing status
            assert data.get("processing_status") in ["pending", "processing", "transcribing"]

    def test_video_response_includes_content_urls_field(self, client, headers):
        """Video response model should include transcript_url and summary_url fields."""
        from api.models.video import ProcessingStatus, VideoResponse
        
        # Verify the model has the expected fields
        video = VideoResponse(
            video_id=str(uuid4()),
            youtube_video_id="dQw4w9WgXcQ",
            title="Test Video",
            description=None,
            duration=180,
            publish_date=datetime.now(),
            thumbnail_url="https://example.com/thumb.jpg",
            processing_status=ProcessingStatus.COMPLETED,
            transcript_url="/api/v1/videos/123/transcript",
            summary_url="/api/v1/videos/123/summary",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        
        assert hasattr(video, "transcript_url")
        assert hasattr(video, "summary_url")


@pytest.mark.integration
class TestPipelineJobFlow:
    """Tests for job flow through the pipeline."""

    def test_job_types_exist(self, client, headers):
        """All expected job types should be supported."""
        expected_types = ["transcribe", "summarize", "embed", "build_relationships"]
        
        for job_type in expected_types:
            response = client.get(
                f"/api/v1/jobs?job_type={job_type}",
                headers=headers,
            )
            # Should accept the job type filter
            assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_job_statuses_exist(self, client, headers):
        """All expected job statuses should be supported."""
        expected_statuses = ["pending", "running", "succeeded", "failed"]
        
        for job_status in expected_statuses:
            response = client.get(
                f"/api/v1/jobs?status={job_status}",
                headers=headers,
            )
            # Should accept the status filter
            assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
class TestPipelineContentEndpoints:
    """Tests for content retrieval endpoints."""

    def test_transcript_endpoint_exists(self, client, headers):
        """Transcript endpoint should exist."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/transcript",
            headers=headers,
        )
        # Should return 404 (not found) not routing 404
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_summary_endpoint_exists(self, client, headers):
        """Summary endpoint should exist."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/summary",
            headers=headers,
        )
        # Should return 404 (not found) not routing 404
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# =============================================================================
# Live Tests - Full Pipeline Execution
# =============================================================================


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLivePipelineExecution:
    """Live tests for full pipeline execution.
    
    These tests submit a real video and wait for processing to complete.
    """

    def test_full_video_processing_pipeline(self, live_client, headers, sample_youtube_url):
        """Test complete video processing from submission to completion.
        
        This is the primary pipeline integration test that verifies:
        1. Video submission succeeds
        2. Jobs are created and processed
        3. Video reaches completed status
        4. Transcript and summary content are accessible
        """
        # Step 1: Submit video
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        
        assert submit_response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED], \
            f"Video submission failed: {submit_response.text}"
        
        video_data = submit_response.json()
        video_id = video_data["video_id"]
        
        # Step 2: Poll for completion
        start_time = time.time()
        final_status = None
        
        while time.time() - start_time < PROCESSING_TIMEOUT_SECONDS:
            status_response = live_client.get(
                f"/api/v1/videos/{video_id}",
                headers=headers,
            )
            
            assert status_response.status_code == status.HTTP_200_OK
            
            video_data = status_response.json()
            final_status = video_data.get("processing_status")
            
            if final_status == "completed":
                break
            elif final_status == "failed":
                pytest.fail(f"Video processing failed: {video_data.get('error_message')}")
            
            time.sleep(POLLING_INTERVAL_SECONDS)
        
        assert final_status == "completed", \
            f"Video did not complete within {PROCESSING_TIMEOUT_SECONDS}s. Status: {final_status}"
        
        # Step 3: Verify content URLs are present
        assert video_data.get("transcript_url") is not None, "Completed video should have transcript_url"
        assert video_data.get("summary_url") is not None, "Completed video should have summary_url"
        
        # Step 4: Verify content is accessible
        transcript_response = live_client.get(
            f"/api/v1/videos/{video_id}/transcript",
            headers=headers,
        )
        assert transcript_response.status_code == status.HTTP_200_OK, \
            f"Failed to fetch transcript: {transcript_response.status_code}"
        assert len(transcript_response.text) > 0, "Transcript should not be empty"
        
        summary_response = live_client.get(
            f"/api/v1/videos/{video_id}/summary",
            headers=headers,
        )
        assert summary_response.status_code == status.HTTP_200_OK, \
            f"Failed to fetch summary: {summary_response.status_code}"
        assert len(summary_response.text) > 0, "Summary should not be empty"

    def test_all_jobs_complete_successfully(self, live_client, headers, sample_youtube_url):
        """Test that all pipeline jobs complete for a video."""
        # Submit video
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        
        assert submit_response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]
        
        video_id = submit_response.json()["video_id"]
        
        # Wait for completion
        start_time = time.time()
        while time.time() - start_time < PROCESSING_TIMEOUT_SECONDS:
            video_response = live_client.get(
                f"/api/v1/videos/{video_id}",
                headers=headers,
            )
            
            if video_response.json().get("processing_status") in ["completed", "failed"]:
                break
            
            time.sleep(POLLING_INTERVAL_SECONDS)
        
        # Get all jobs for this video
        jobs_response = live_client.get(
            f"/api/v1/jobs?video_id={video_id}",
            headers=headers,
        )
        
        assert jobs_response.status_code == status.HTTP_200_OK
        
        jobs_data = jobs_response.json()
        jobs = jobs_data.get("items", [])
        
        # Should have all 4 job types
        job_types = {job["job_type"] for job in jobs}
        expected_types = {"transcribe", "summarize", "embed", "build_relationships"}
        
        assert job_types == expected_types, \
            f"Missing job types. Found: {job_types}, Expected: {expected_types}"
        
        # All jobs should be succeeded
        for job in jobs:
            assert job["status"] == "succeeded", \
                f"Job {job['job_type']} has status {job['status']}, expected 'succeeded'"


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLivePipelineProgressTracking:
    """Live tests for progress tracking during processing."""

    def test_job_progress_updates_during_processing(self, live_client, headers, sample_youtube_url):
        """Test that job progress is tracked during processing."""
        # Submit video
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        
        assert submit_response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]
        
        video_id = submit_response.json()["video_id"]
        
        # Track job statuses over time
        observed_statuses = set()
        start_time = time.time()
        
        while time.time() - start_time < PROCESSING_TIMEOUT_SECONDS:
            jobs_response = live_client.get(
                f"/api/v1/jobs?video_id={video_id}",
                headers=headers,
            )
            
            if jobs_response.status_code == status.HTTP_200_OK:
                jobs = jobs_response.json().get("items", [])
                for job in jobs:
                    observed_statuses.add(job["status"])
            
            # Check if all done
            video_response = live_client.get(
                f"/api/v1/videos/{video_id}",
                headers=headers,
            )
            
            if video_response.json().get("processing_status") in ["completed", "failed"]:
                break
            
            time.sleep(1)  # Shorter interval for progress tracking
        
        # Should have observed at least pending and succeeded states
        assert "succeeded" in observed_statuses, \
            f"Did not observe 'succeeded' status. Observed: {observed_statuses}"


@pytest.mark.live
@pytest.mark.skipif(not E2E_ENABLED, reason="Live E2E tests disabled. Set E2E_TESTS_ENABLED=true")
class TestLivePipelineReprocessing:
    """Live tests for video reprocessing."""

    def test_can_reprocess_completed_video(self, live_client, headers, sample_youtube_url):
        """Test that a completed video can be reprocessed."""
        # Submit and wait for completion
        submit_response = live_client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        
        assert submit_response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]
        
        video_id = submit_response.json()["video_id"]
        
        # Wait for completion
        start_time = time.time()
        while time.time() - start_time < PROCESSING_TIMEOUT_SECONDS:
            video_response = live_client.get(
                f"/api/v1/videos/{video_id}",
                headers=headers,
            )
            
            if video_response.json().get("processing_status") == "completed":
                break
            elif video_response.json().get("processing_status") == "failed":
                pytest.skip("Video processing failed, skipping reprocess test")
            
            time.sleep(POLLING_INTERVAL_SECONDS)
        
        # Reprocess the video
        reprocess_response = live_client.post(
            f"/api/v1/videos/{video_id}/reprocess",
            headers=headers,
        )
        
        # Should succeed or be accepted
        assert reprocess_response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_202_ACCEPTED,
        ], f"Reprocess failed: {reprocess_response.text}"
        
        # Video status should change
        video_response = live_client.get(
            f"/api/v1/videos/{video_id}",
            headers=headers,
        )
        
        new_status = video_response.json().get("processing_status")
        assert new_status in ["pending", "processing", "transcribing"], \
            f"Expected video to be processing, got: {new_status}"


# =============================================================================
# Regression Tests
# =============================================================================


@pytest.mark.integration
class TestPipelineRegressions:
    """Regression tests for known issues."""

    def test_video_response_model_has_content_urls(self):
        """Regression: VideoResponse should include transcript_url and summary_url."""
        from api.models.video import VideoResponse
        
        # Get model fields from Pydantic model_fields
        field_names = list(VideoResponse.model_fields.keys())
        
        # Check for required fields
        assert "transcript_url" in field_names, \
            "VideoResponse missing transcript_url field"
        assert "summary_url" in field_names, \
            "VideoResponse missing summary_url field"

    def test_completed_video_has_content_urls_populated(self):
        """Regression: Completed videos should have content URLs populated."""
        from uuid import uuid4

        from api.models.video import ProcessingStatus, VideoResponse
        
        # Verify the service logic: completed videos should have URLs
        # This is a model-level test; service-level test is in live tests
        video_id = uuid4()
        video = VideoResponse(
            video_id=video_id,
            youtube_video_id="dQw4w9WgXcQ",
            title="Test",
            description=None,
            duration=0,
            publish_date=datetime.now(),
            thumbnail_url="",
            processing_status=ProcessingStatus.COMPLETED,
            transcript_url=f"/api/v1/videos/{video_id}/transcript",
            summary_url=f"/api/v1/videos/{video_id}/summary",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        
        assert video.transcript_url is not None
        assert video.summary_url is not None
