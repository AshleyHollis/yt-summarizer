"""Tests for Pydantic models."""

from datetime import datetime, UTC
from uuid import uuid4

import pytest
from pydantic import ValidationError

from api.models.video import (
    SubmitVideoRequest,
    ChannelSummary,
    ProcessingStatus,
    extract_youtube_video_id,
)
from api.models.job import (
    JobType,
    JobStage,
    JobStatus,
    JobResponse,
    JobSummaryResponse,
    VideoJobsProgress,
    RetryJobRequest,
)


class TestExtractYoutubeVideoId:
    """Tests for YouTube video ID extraction."""

    @pytest.mark.parametrize("url,expected_id", [
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("http://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://www.youtube.com/embed/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://www.youtube.com/v/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s", "dQw4w9WgXcQ"),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLtest", "dQw4w9WgXcQ"),
    ])
    def test_extract_valid_video_ids(self, url: str, expected_id: str):
        """Test extracting video ID from various valid YouTube URL formats."""
        assert extract_youtube_video_id(url) == expected_id

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://vimeo.com/12345678",
        "not-a-url",
        "https://youtube.com/watch",
    ])
    def test_extract_returns_none_for_invalid_urls(self, url: str):
        """Test that None is returned for invalid URLs."""
        assert extract_youtube_video_id(url) is None


class TestSubmitVideoRequest:
    """Tests for SubmitVideoRequest model."""

    def test_valid_youtube_url_accepted(self):
        """Test that a valid YouTube URL is accepted."""
        request = SubmitVideoRequest(url="https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert request.url == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    def test_short_youtube_url_accepted(self):
        """Test that a short YouTube URL is accepted."""
        request = SubmitVideoRequest(url="https://youtu.be/dQw4w9WgXcQ")
        assert request.url == "https://youtu.be/dQw4w9WgXcQ"

    def test_embed_youtube_url_accepted(self):
        """Test that an embed YouTube URL is accepted."""
        request = SubmitVideoRequest(url="https://www.youtube.com/embed/dQw4w9WgXcQ")
        assert request.url == "https://www.youtube.com/embed/dQw4w9WgXcQ"

    def test_invalid_url_rejected(self):
        """Test that an invalid URL is rejected."""
        with pytest.raises(ValidationError):
            SubmitVideoRequest(url="not-a-valid-url")

    def test_empty_url_rejected(self):
        """Test that an empty URL is rejected."""
        with pytest.raises(ValidationError):
            SubmitVideoRequest(url="")

    def test_non_youtube_url_rejected(self):
        """Test that a non-YouTube URL is rejected."""
        with pytest.raises(ValidationError):
            SubmitVideoRequest(url="https://vimeo.com/12345678")


class TestProcessingStatus:
    """Tests for ProcessingStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist."""
        # Get all status values from the enum
        status_values = [s.value for s in ProcessingStatus]
        # Should have the core statuses
        assert "pending" in status_values
        assert "processing" in status_values or "running" in status_values
        assert len(status_values) >= 2


class TestChannelSummary:
    """Tests for ChannelSummary model."""

    def test_valid_channel_summary(self):
        """Test creating a valid channel summary."""
        summary = ChannelSummary(
            channel_id=uuid4(),
            name="Test Channel",
            youtube_channel_id="UCtest123",
        )
        assert summary.name == "Test Channel"

    def test_channel_id_required(self):
        """Test that channel_id is required."""
        with pytest.raises(ValidationError):
            ChannelSummary(name="Test Channel", youtube_channel_id="UCtest123")


class TestJobType:
    """Tests for JobType enum."""

    def test_all_job_types_exist(self):
        """Test that all expected job types exist."""
        assert JobType.TRANSCRIBE is not None
        assert JobType.SUMMARIZE is not None
        assert JobType.EMBED is not None
        assert JobType.BUILD_RELATIONSHIPS is not None


class TestJobStage:
    """Tests for JobStage enum."""

    def test_all_stages_exist(self):
        """Test that all expected stages exist."""
        assert JobStage.QUEUED is not None
        assert JobStage.RUNNING is not None
        assert JobStage.COMPLETED is not None
        assert JobStage.FAILED is not None


class TestJobStatus:
    """Tests for JobStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert JobStatus.PENDING is not None
        assert JobStatus.RUNNING is not None
        assert JobStatus.SUCCEEDED is not None
        assert JobStatus.FAILED is not None


class TestRetryJobRequest:
    """Tests for RetryJobRequest model."""

    def test_valid_request(self):
        """Test creating a valid retry job request."""
        request = RetryJobRequest()
        assert request is not None


class TestVideoJobsProgress:
    """Tests for VideoJobsProgress model."""

    def test_valid_progress(self):
        """Test creating valid video jobs progress."""
        video_id = uuid4()
        
        jobs = [
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.TRANSCRIBE,
                stage=JobStage.COMPLETED,
                status=JobStatus.SUCCEEDED,
                created_at=datetime.now(UTC),
            ),
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.SUMMARIZE,
                stage=JobStage.RUNNING,
                status=JobStatus.RUNNING,
                created_at=datetime.now(UTC),
            ),
        ]
        progress = VideoJobsProgress(
            video_id=video_id,
            overall_status="processing",
            overall_progress=25,
            jobs=jobs,
        )
        assert progress.overall_progress == 25
        assert len(progress.jobs) == 2

    def test_progress_bounds(self):
        """Test that progress is within bounds."""
        with pytest.raises(ValidationError):
            VideoJobsProgress(
                video_id=uuid4(),
                overall_status="invalid",
                overall_progress=150,  # Invalid - over 100
                jobs=[],
            )

    def test_is_complete_property(self):
        """Test the is_complete property."""
        video_id = uuid4()
        
        # All jobs completed
        jobs = [
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.TRANSCRIBE,
                stage=JobStage.COMPLETED,
                status=JobStatus.SUCCEEDED,
                created_at=datetime.now(UTC),
            ),
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.SUMMARIZE,
                stage=JobStage.COMPLETED,
                status=JobStatus.SUCCEEDED,
                created_at=datetime.now(UTC),
            ),
        ]
        progress = VideoJobsProgress(
            video_id=video_id,
            overall_status="completed",
            overall_progress=100,
            jobs=jobs,
        )
        assert progress.is_complete is True

    def test_has_failed_property(self):
        """Test the has_failed property."""
        video_id = uuid4()
        
        # One job failed
        jobs = [
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.TRANSCRIBE,
                stage=JobStage.COMPLETED,
                status=JobStatus.SUCCEEDED,
                created_at=datetime.now(UTC),
            ),
            JobSummaryResponse(
                job_id=uuid4(),
                video_id=video_id,
                job_type=JobType.SUMMARIZE,
                stage=JobStage.FAILED,
                status=JobStatus.FAILED,
                created_at=datetime.now(UTC),
            ),
        ]
        progress = VideoJobsProgress(
            video_id=video_id,
            overall_status="failed",
            overall_progress=50,
            jobs=jobs,
        )
        assert progress.has_failed is True
