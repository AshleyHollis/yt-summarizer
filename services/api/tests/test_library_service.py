"""Unit tests for LibraryService.

These tests verify the internal logic of LibraryService, particularly:
- Blob URI parsing and extraction
- Summary content fetching
- Artifact handling
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

# ============================================================================
# Blob URI Extraction Tests
# ============================================================================


class TestBlobUriExtraction:
    """Tests for extracting blob names from blob URIs.
    
    CRITICAL: These tests prevent regression of the bug where blob names
    were incorrectly extracted, causing 404 errors when fetching summaries.
    
    The blob storage structure is:
        container/{video_id}/{youtube_video_id}_summary.md
    
    The blob_uri stored in artifacts is the full URL:
        http://host/account/container/{video_id}/{youtube_video_id}_summary.md
    
    We need to extract the path after the container name:
        {video_id}/{youtube_video_id}_summary.md
    """

    @pytest.mark.parametrize("blob_uri,expected_blob_name", [
        # Standard Azurite local development URL
        (
            "http://127.0.0.1:62442/devstoreaccount1/summaries/a7311eb9-a007-4b78-9610-a4dc85da1cdb/hzkm3hM8FUg_summary.md",
            "a7311eb9-a007-4b78-9610-a4dc85da1cdb/hzkm3hM8FUg_summary.md"
        ),
        # Azure Blob Storage production URL
        (
            "https://myaccount.blob.core.windows.net/summaries/a7311eb9-a007-4b78-9610-a4dc85da1cdb/hzkm3hM8FUg_summary.md",
            "a7311eb9-a007-4b78-9610-a4dc85da1cdb/hzkm3hM8FUg_summary.md"
        ),
        # URL with different video ID format
        (
            "http://localhost:10000/devstoreaccount1/summaries/550e8400-e29b-41d4-a716-446655440000/dQw4w9WgXcQ_summary.md",
            "550e8400-e29b-41d4-a716-446655440000/dQw4w9WgXcQ_summary.md"
        ),
        # URL with special characters in YouTube video ID (underscore, hyphen)
        (
            "http://127.0.0.1:62442/devstoreaccount1/summaries/a7311eb9-a007-4b78-9610-a4dc85da1cdb/-35JXpiQ3EA_summary.md",
            "a7311eb9-a007-4b78-9610-a4dc85da1cdb/-35JXpiQ3EA_summary.md"
        ),
    ])
    def test_extract_blob_name_with_video_id_prefix(self, blob_uri: str, expected_blob_name: str):
        """Test that blob name is correctly extracted with the video_id folder prefix.
        
        REGRESSION TEST: This test would have caught the bug where we only took
        the filename (e.g., "hzkm3hM8FUg_summary.md") instead of the full path
        (e.g., "a7311eb9-xxx/hzkm3hM8FUg_summary.md").
        """
        from shared.blob.client import SUMMARIES_CONTAINER
        
        # This is the logic from LibraryService.get_video_detail
        parts = blob_uri.split(f"/{SUMMARIES_CONTAINER}/")
        blob_name = parts[1] if len(parts) > 1 else blob_uri.split("/")[-1]
        
        assert blob_name == expected_blob_name, (
            f"Expected blob name '{expected_blob_name}' but got '{blob_name}'. "
            f"The blob name must include the video_id folder prefix for correct blob lookup."
        )

    def test_extract_blob_name_preserves_video_id_folder(self):
        """Test that the video_id folder is preserved in the blob name.
        
        CRITICAL: The summarize worker stores blobs as:
            {video_id}/{youtube_video_id}_summary.md
        
        The library service must extract this full path, not just the filename.
        """
        from shared.blob.client import SUMMARIES_CONTAINER
        
        video_id = "a7311eb9-a007-4b78-9610-a4dc85da1cdb"
        youtube_video_id = "hzkm3hM8FUg"
        blob_uri = f"http://127.0.0.1:62442/devstoreaccount1/{SUMMARIES_CONTAINER}/{video_id}/{youtube_video_id}_summary.md"
        
        parts = blob_uri.split(f"/{SUMMARIES_CONTAINER}/")
        blob_name = parts[1] if len(parts) > 1 else blob_uri.split("/")[-1]
        
        # MUST include video_id folder
        assert video_id in blob_name, (
            f"Blob name '{blob_name}' must include video_id '{video_id}'. "
            f"Without the video_id folder, blob lookups will fail with 404."
        )
        
        # MUST include youtube_video_id
        assert youtube_video_id in blob_name, (
            f"Blob name '{blob_name}' must include youtube_video_id '{youtube_video_id}'."
        )

    def test_broken_extraction_only_takes_filename(self):
        """Demonstrate the bug: taking only the last path segment loses the folder.
        
        This test documents the INCORRECT behavior that caused 404 errors.
        """
        blob_uri = "http://127.0.0.1:62442/devstoreaccount1/summaries/a7311eb9-a007-4b78-9610-a4dc85da1cdb/hzkm3hM8FUg_summary.md"
        
        # BROKEN: This was the old (incorrect) behavior
        broken_blob_name = blob_uri.split("/")[-1]
        
        # This only gives us "hzkm3hM8FUg_summary.md" - missing the video_id folder!
        assert broken_blob_name == "hzkm3hM8FUg_summary.md"
        assert "a7311eb9" not in broken_blob_name, (
            "The broken extraction loses the video_id folder prefix"
        )

    def test_fallback_for_simple_blob_name(self):
        """Test fallback when blob_uri is just a simple name (edge case)."""
        from shared.blob.client import SUMMARIES_CONTAINER
        
        # If for some reason the blob_uri is just a filename
        blob_uri = "simple_summary.md"
        
        parts = blob_uri.split(f"/{SUMMARIES_CONTAINER}/")
        blob_name = parts[1] if len(parts) > 1 else blob_uri.split("/")[-1]
        
        # Should fall back to using the whole thing as blob name
        assert blob_name == "simple_summary.md"


# ============================================================================
# Video Detail Summary Fetching Tests
# ============================================================================


class TestGetVideoDetailSummaryFetching:
    """Tests for the get_video_detail method's summary fetching logic."""

    @pytest.fixture
    def mock_video_with_summary_artifact(self):
        """Create a mock video with a summary artifact."""
        video_id = uuid4()
        youtube_video_id = "hzkm3hM8FUg"
        
        # Mock channel
        channel = MagicMock()
        channel.channel_id = uuid4()
        channel.youtube_channel_id = "UC12345"
        channel.name = "Test Channel"
        channel.thumbnail_url = None
        
        # Mock summary artifact with full blob URI
        summary_artifact = MagicMock()
        summary_artifact.artifact_id = uuid4()
        summary_artifact.artifact_type = "summary"
        summary_artifact.blob_uri = f"http://127.0.0.1:62442/devstoreaccount1/summaries/{video_id}/{youtube_video_id}_summary.md"
        summary_artifact.content_length = 3000
        summary_artifact.model_name = "gpt-4o-mini"
        summary_artifact.created_at = datetime.now(UTC)
        
        # Mock video
        video = MagicMock()
        video.video_id = video_id
        video.youtube_video_id = youtube_video_id
        video.title = "Test Video"
        video.description = "Test description"
        video.channel = channel
        video.channel_id = channel.channel_id
        video.duration = 300
        video.publish_date = datetime.now(UTC)
        video.thumbnail_url = "https://example.com/thumb.jpg"
        video.processing_status = "completed"
        video.created_at = datetime.now(UTC)
        video.updated_at = datetime.now(UTC)
        video.artifacts = [summary_artifact]
        
        return video, str(video_id), youtube_video_id

    @pytest.mark.asyncio
    async def test_summary_fetched_with_correct_blob_path(self, mock_video_with_summary_artifact):
        """Test that summary is fetched using the correct blob path including video_id folder."""
        video, video_id, youtube_video_id = mock_video_with_summary_artifact
        
        # Create mock session that returns different results for different queries
        mock_session = AsyncMock()
        
        # For the video query (first call)
        mock_video_result = MagicMock()
        mock_video_result.scalar_one_or_none.return_value = video
        
        # For count queries (segment_count, relationship_count)
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0
        
        # Configure execute to return video result first, then count results
        call_count = 0
        async def mock_execute(query):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_video_result
            return mock_count_result
        
        mock_session.execute = mock_execute
        
        # Mock blob client
        expected_blob_name = f"{video_id}/{youtube_video_id}_summary.md"
        mock_summary_content = b"# Test Summary\n\nThis is the summary content."
        
        with patch("api.services.library_service.BlobClient") as MockBlobClient:
            mock_blob_instance = MagicMock()
            mock_blob_instance.download_blob.return_value = mock_summary_content
            MockBlobClient.return_value = mock_blob_instance
            
            from api.services.library_service import LibraryService
            
            service = LibraryService(mock_session)
            
            # Mock the helper methods that aren't relevant to this test
            service._get_video_facets = AsyncMock(return_value={})
            
            result = await service.get_video_detail(video_id)
            
            # Verify blob client was called with the CORRECT blob name (including video_id folder)
            mock_blob_instance.download_blob.assert_called_once()
            call_args = mock_blob_instance.download_blob.call_args
            actual_blob_name = call_args[0][1]  # Second positional argument is blob_name
            
            assert actual_blob_name == expected_blob_name, (
                f"Expected blob name '{expected_blob_name}' but got '{actual_blob_name}'. "
                f"The blob name must include the video_id folder for correct lookup."
            )

    @pytest.mark.asyncio
    async def test_summary_content_included_in_response(self, mock_video_with_summary_artifact):
        """Test that the fetched summary content is included in the response."""
        video, video_id, youtube_video_id = mock_video_with_summary_artifact
        
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = video
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        mock_summary_content = b"# Test Summary\n\nThis is the summary content."
        
        with patch("api.services.library_service.BlobClient") as MockBlobClient:
            mock_blob_instance = MagicMock()
            mock_blob_instance.download_blob.return_value = mock_summary_content
            MockBlobClient.return_value = mock_blob_instance
            
            from api.services.library_service import LibraryService
            
            service = LibraryService(mock_session)
            service._get_video_facets = AsyncMock(return_value={})
            
            result = await service.get_video_detail(video_id)
            
            assert result.summary == mock_summary_content.decode("utf-8"), (
                "The summary content should be included in the response"
            )

    @pytest.mark.asyncio
    async def test_summary_null_when_blob_not_found(self, mock_video_with_summary_artifact):
        """Test that summary is null when blob fetch fails (e.g., 404)."""
        video, video_id, youtube_video_id = mock_video_with_summary_artifact
        
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = video
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        with patch("api.services.library_service.BlobClient") as MockBlobClient:
            mock_blob_instance = MagicMock()
            mock_blob_instance.download_blob.side_effect = Exception("BlobNotFound")
            MockBlobClient.return_value = mock_blob_instance
            
            from api.services.library_service import LibraryService
            
            service = LibraryService(mock_session)
            service._get_video_facets = AsyncMock(return_value={})
            
            result = await service.get_video_detail(video_id)
            
            assert result.summary is None, (
                "Summary should be None when blob fetch fails"
            )

    @pytest.mark.asyncio
    async def test_summary_null_when_no_artifact(self):
        """Test that summary is null when video has no summary artifact."""
        video_id = uuid4()
        
        # Mock video without artifacts
        channel = MagicMock()
        channel.channel_id = uuid4()
        channel.youtube_channel_id = "UC12345"
        channel.name = "Test Channel"
        channel.thumbnail_url = None
        
        video = MagicMock()
        video.video_id = video_id
        video.youtube_video_id = "test123"
        video.title = "Test Video"
        video.description = "Test description"
        video.channel = channel
        video.channel_id = channel.channel_id
        video.duration = 300
        video.publish_date = datetime.now(UTC)
        video.thumbnail_url = "https://example.com/thumb.jpg"
        video.processing_status = "pending"
        video.created_at = datetime.now(UTC)
        video.updated_at = datetime.now(UTC)
        video.artifacts = []  # No artifacts
        
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = video
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        with patch("api.services.library_service.BlobClient") as MockBlobClient:
            from api.services.library_service import LibraryService
            
            service = LibraryService(mock_session)
            service._get_video_facets = AsyncMock(return_value={})
            
            result = await service.get_video_detail(str(video_id))
            
            # Should not have called blob client at all
            MockBlobClient.return_value.download_blob.assert_not_called()
            
            assert result.summary is None, (
                "Summary should be None when video has no summary artifact"
            )


# ============================================================================
# Completed Status Validation Tests
# ============================================================================


class TestCompletedStatusValidation:
    """Tests to ensure videos marked as 'completed' have their summaries accessible.
    
    These tests verify the contract: if a video is marked as completed,
    its summary should be fetchable from blob storage.
    """

    @pytest.mark.asyncio
    async def test_completed_video_with_artifact_should_have_summary(self):
        """A completed video with a summary artifact should return the summary content.
        
        This is the expected happy path: completed videos should have
        accessible summaries.
        """
        video_id = uuid4()
        youtube_video_id = "testVideo123"
        
        # Create a properly completed video
        channel = MagicMock()
        channel.channel_id = uuid4()
        channel.youtube_channel_id = "UC12345"
        channel.name = "Test Channel"
        channel.thumbnail_url = None
        
        summary_artifact = MagicMock()
        summary_artifact.artifact_id = uuid4()
        summary_artifact.artifact_type = "summary"
        summary_artifact.blob_uri = f"http://localhost/summaries/{video_id}/{youtube_video_id}_summary.md"
        summary_artifact.content_length = 1000
        summary_artifact.model_name = "gpt-4"
        summary_artifact.created_at = datetime.now(UTC)
        
        video = MagicMock()
        video.video_id = video_id
        video.youtube_video_id = youtube_video_id
        video.title = "Completed Video"
        video.description = "A properly completed video"
        video.channel = channel
        video.channel_id = channel.channel_id
        video.duration = 600
        video.publish_date = datetime.now(UTC)
        video.thumbnail_url = "https://example.com/thumb.jpg"
        video.processing_status = "completed"  # Key: marked as completed
        video.created_at = datetime.now(UTC)
        video.updated_at = datetime.now(UTC)
        video.artifacts = [summary_artifact]  # Key: has summary artifact
        
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = video
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        expected_summary = "# Summary\n\nThis is the actual summary content."
        
        with patch("api.services.library_service.BlobClient") as MockBlobClient:
            mock_blob_instance = MagicMock()
            mock_blob_instance.download_blob.return_value = expected_summary.encode("utf-8")
            MockBlobClient.return_value = mock_blob_instance
            
            from api.services.library_service import LibraryService
            
            service = LibraryService(mock_session)
            service._get_video_facets = AsyncMock(return_value={})
            
            result = await service.get_video_detail(str(video_id))
            
            # A completed video should have its summary content
            assert result.processing_status == "completed"
            assert result.summary is not None, (
                "Completed video with summary artifact should have summary content. "
                "If this fails, check that blob_name extraction includes the video_id folder."
            )
            assert result.summary == expected_summary
