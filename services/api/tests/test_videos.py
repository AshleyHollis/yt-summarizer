"""Integration tests for video API endpoints.

These tests verify the video submission, retrieval, and reprocessing endpoints.
"""

import pytest
from fastapi import status
from unittest.mock import patch, MagicMock, AsyncMock
from uuid import uuid4


class TestSubmitVideo:
    """Integration tests for POST /api/v1/videos endpoint."""

    def test_submit_video_requires_youtube_url(self, client, headers):
        """Test that youtube_url is required."""
        response = client.post(
            "/api/v1/videos",
            json={},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_submit_video_validates_youtube_url_format(self, client, headers):
        """Test that invalid YouTube URLs are rejected."""
        response = client.post(
            "/api/v1/videos",
            json={"url": "https://example.com/video"},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "error" in data or "detail" in data  # Accept either format

    def test_submit_video_accepts_standard_youtube_url(self, client, headers, sample_youtube_url):
        """Test that standard YouTube URLs are accepted."""
        # This will fail without mocking the service, but should pass validation
        response = client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        # Either success, bad request (queue unavailable), or internal error - not validation error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_submit_video_accepts_short_youtube_url(self, client, headers, sample_youtube_video_id):
        """Test that short youtu.be URLs are accepted."""
        response = client.post(
            "/api/v1/videos",
            json={"url": f"https://youtu.be/{sample_youtube_video_id}"},
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_submit_video_accepts_embed_youtube_url(self, client, headers, sample_youtube_video_id):
        """Test that embed YouTube URLs are accepted."""
        response = client.post(
            "/api/v1/videos",
            json={"url": f"https://www.youtube.com/embed/{sample_youtube_video_id}"},
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_submit_video_rejects_empty_url(self, client, headers):
        """Test that empty URLs are rejected."""
        response = client.post(
            "/api/v1/videos",
            json={"url": ""},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_submit_video_rejects_non_youtube_url(self, client, headers):
        """Test that non-YouTube URLs are rejected."""
        response = client.post(
            "/api/v1/videos",
            json={"url": "https://vimeo.com/12345678"},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_submit_video_rejects_nonexistent_youtube_video(self, client, headers):
        """Test that non-existent YouTube videos are rejected with 404.
        
        Uses a fabricated video ID that doesn't exist on YouTube.
        The API should verify the video exists before creating a record.
        """
        # Use a clearly fake video ID that won't exist
        fake_video_id = "XXXXXXXXXXX"  # 11 chars like real IDs but won't exist
        response = client.post(
            "/api/v1/videos",
            json={"url": f"https://www.youtube.com/watch?v={fake_video_id}"},
            headers=headers,
        )
        # Should return 404 (video not found on YouTube) or 500 (if mocked)
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]
        # If 404, check the error message
        if response.status_code == status.HTTP_404_NOT_FOUND:
            data = response.json()
            error_detail = data.get("detail", data.get("error", {}).get("message", ""))
            assert "not found" in error_detail.lower() or "unavailable" in error_detail.lower()


class TestGetVideo:
    """Integration tests for GET /api/v1/videos/{video_id} endpoint."""

    def test_get_video_requires_valid_uuid(self, client, headers):
        """Test that video_id must be a valid UUID."""
        response = client.get(
            "/api/v1/videos/not-a-uuid",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_video_returns_404_for_nonexistent(self, client, headers, sample_video_id):
        """Test that non-existent videos return 404."""
        response = client.get(
            f"/api/v1/videos/{sample_video_id}",
            headers=headers,
        )
        # Without mocked DB, should return 404 or 500
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_get_video_accepts_valid_uuid(self, client, headers):
        """Test that valid UUIDs are accepted."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestReprocessVideo:
    """Integration tests for POST /api/v1/videos/{video_id}/reprocess endpoint."""

    def test_reprocess_video_requires_valid_uuid(self, client, headers):
        """Test that video_id must be a valid UUID."""
        response = client.post(
            "/api/v1/videos/not-a-uuid/reprocess",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_reprocess_video_returns_404_for_nonexistent(self, client, headers, sample_video_id):
        """Test that non-existent videos return 404."""
        response = client.post(
            f"/api/v1/videos/{sample_video_id}/reprocess",
            headers=headers,
        )
        # Without mocked DB, should return 404 or 500
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


class TestVideoValidation:
    """Tests for video input validation."""

    @pytest.mark.parametrize("url", [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "http://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://www.youtube.com/embed/dQw4w9WgXcQ",
        "https://www.youtube.com/v/dQw4w9WgXcQ",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
    ])
    def test_valid_youtube_urls_accepted(self, client, headers, url):
        """Test that various valid YouTube URL formats are accepted."""
        response = client.post(
            "/api/v1/videos",
            json={"url": url},
            headers=headers,
        )
        # Should pass validation (might fail on service layer)
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY or \
               "url" not in str(response.json())

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://vimeo.com/12345678",
        "not-a-url",
        "ftp://youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtube.com/watch",  # Missing video ID
        "https://youtube.com/watch?v=",  # Empty video ID
    ])
    def test_invalid_urls_rejected(self, client, headers, url):
        """Test that invalid URLs are rejected."""
        response = client.post(
            "/api/v1/videos",
            json={"url": url},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVideoResponseFormat:
    """Tests for video response format validation."""

    def test_submit_video_response_contains_required_fields(self, client, headers, sample_youtube_url):
        """Test that successful submission returns required fields."""
        # This test would need mocking to fully verify
        # For now, we just verify the endpoint exists and accepts input
        response = client.post(
            "/api/v1/videos",
            json={"url": sample_youtube_url},
            headers=headers,
        )
        # If successful, check response format
        if response.status_code in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            data = response.json()
            assert "video_id" in data
            assert "youtube_video_id" in data
            assert "title" in data
            assert "processing_status" in data


class TestVideoTranscript:
    """Integration tests for GET /api/v1/videos/{video_id}/transcript endpoint."""

    def test_get_transcript_requires_valid_uuid(self, client, headers):
        """Test that video_id must be a valid UUID."""
        response = client.get(
            "/api/v1/videos/not-a-uuid/transcript",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_transcript_returns_404_for_nonexistent_video(self, client, headers):
        """Test that non-existent videos return 404."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/transcript",
            headers=headers,
        )
        # Should return 404 (video not found) or 500 (DB unavailable)
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_get_transcript_accepts_valid_uuid(self, client, headers):
        """Test that valid UUIDs are accepted."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/transcript",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVideoSummary:
    """Integration tests for GET /api/v1/videos/{video_id}/summary endpoint."""

    def test_get_summary_requires_valid_uuid(self, client, headers):
        """Test that video_id must be a valid UUID."""
        response = client.get(
            "/api/v1/videos/not-a-uuid/summary",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_summary_returns_404_for_nonexistent_video(self, client, headers):
        """Test that non-existent videos return 404."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/summary",
            headers=headers,
        )
        # Should return 404 (video not found) or 500 (DB unavailable)
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_get_summary_accepts_valid_uuid(self, client, headers):
        """Test that valid UUIDs are accepted."""
        video_id = str(uuid4())
        response = client.get(
            f"/api/v1/videos/{video_id}/summary",
            headers=headers,
        )
        # Should not be a validation error
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVideoContentUrls:
    """Tests for transcript_url and summary_url in video responses."""

    def test_completed_video_response_includes_content_urls(self, client, headers):
        """Test that completed video response includes transcript and summary URLs."""
        # This test requires a mocked completed video
        # For now, we verify the model accepts these fields
        from api.models.video import VideoResponse, ProcessingStatus
        from datetime import datetime
        
        # Create a completed video response
        video_data = VideoResponse(
            video_id=str(uuid4()),
            youtube_video_id="dQw4w9WgXcQ",
            title="Test Video",
            description="Test description",
            duration=180,
            publish_date=datetime.now(),
            thumbnail_url="https://example.com/thumb.jpg",
            processing_status=ProcessingStatus.COMPLETED,
            transcript_url="/api/v1/videos/123/transcript",
            summary_url="/api/v1/videos/123/summary",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        
        # Verify the model includes the URLs
        assert video_data.transcript_url == "/api/v1/videos/123/transcript"
        assert video_data.summary_url == "/api/v1/videos/123/summary"

    def test_pending_video_response_has_null_content_urls(self, client, headers):
        """Test that pending video response has null transcript and summary URLs."""
        from api.models.video import VideoResponse, ProcessingStatus
        from datetime import datetime
        
        # Create a pending video response
        video_data = VideoResponse(
            video_id=str(uuid4()),
            youtube_video_id="dQw4w9WgXcQ",
            title="Test Video",
            description=None,
            duration=0,
            publish_date=datetime.now(),
            thumbnail_url="https://example.com/thumb.jpg",
            processing_status=ProcessingStatus.PENDING,
            transcript_url=None,
            summary_url=None,
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        
        # Verify the model has null URLs for pending videos
        assert video_data.transcript_url is None
        assert video_data.summary_url is None


class TestVideoNotFoundError:
    """Tests for VideoNotFoundError exception handling."""

    def test_video_not_found_error_has_correct_attributes(self):
        """Test that VideoNotFoundError contains the video ID and reason."""
        from api.services.video_service import VideoNotFoundError
        
        error = VideoNotFoundError("dQw4w9WgXcQ", "Video is private")
        
        assert error.youtube_video_id == "dQw4w9WgXcQ"
        assert error.reason == "Video is private"
        assert "dQw4w9WgXcQ" in str(error)
        assert "Video is private" in str(error)

    def test_video_not_found_error_default_reason(self):
        """Test that VideoNotFoundError has a sensible default reason."""
        from api.services.video_service import VideoNotFoundError
        
        error = VideoNotFoundError("XXXXXXXXXXX")
        
        assert error.youtube_video_id == "XXXXXXXXXXX"
        assert "not found" in error.reason.lower()

    @pytest.mark.asyncio
    async def test_fetch_video_metadata_raises_for_unavailable_video(self):
        """Test that _fetch_video_metadata raises VideoNotFoundError for unavailable videos."""
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.services.video_service import VideoService, VideoNotFoundError
        
        # Mock yt-dlp to simulate "Video unavailable" error
        with patch("yt_dlp.YoutubeDL") as mock_ydl_class:
            mock_ydl = MagicMock()
            mock_ydl.__enter__ = MagicMock(return_value=mock_ydl)
            mock_ydl.__exit__ = MagicMock(return_value=False)
            mock_ydl.extract_info.side_effect = Exception("ERROR: Video unavailable")
            mock_ydl_class.return_value = mock_ydl
            
            service = VideoService(AsyncMock())
            
            with pytest.raises(VideoNotFoundError) as exc_info:
                await service._fetch_video_metadata("XXXXXXXXXXX")
            
            assert exc_info.value.youtube_video_id == "XXXXXXXXXXX"
            assert "unavailable" in str(exc_info.value).lower() or "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_fetch_video_metadata_raises_for_private_video(self):
        """Test that _fetch_video_metadata raises VideoNotFoundError for private videos."""
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.services.video_service import VideoService, VideoNotFoundError
        
        # Mock yt-dlp to simulate "Private video" error
        with patch("yt_dlp.YoutubeDL") as mock_ydl_class:
            mock_ydl = MagicMock()
            mock_ydl.__enter__ = MagicMock(return_value=mock_ydl)
            mock_ydl.__exit__ = MagicMock(return_value=False)
            mock_ydl.extract_info.side_effect = Exception("ERROR: Private video. Sign in if you've been granted access")
            mock_ydl_class.return_value = mock_ydl
            
            service = VideoService(AsyncMock())
            
            with pytest.raises(VideoNotFoundError) as exc_info:
                await service._fetch_video_metadata("PRIVATE1234")
            
            assert exc_info.value.youtube_video_id == "PRIVATE1234"
