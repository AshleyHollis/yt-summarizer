"""Tests for blob storage helper functions."""

from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import ResourceNotFoundError

from shared.blob.client import (
    LIBRARY_CONTAINER,
    SUMMARIES_CONTAINER,
    BlobClient,
    extract_blob_name_from_uri,
    get_metadata_blob_path,
    get_segments_blob_path,
    get_summary_blob_path,
    get_transcript_blob_path,
    get_video_folder_path,
    sanitize_channel_name,
)


class TestSanitizeChannelName:
    """Tests for sanitize_channel_name function."""

    def test_simple_name(self):
        """Test simple channel name."""
        assert sanitize_channel_name("TestChannel") == "testchannel"

    def test_name_with_spaces(self):
        """Test channel name with spaces."""
        assert sanitize_channel_name("Test Channel") == "test-channel"

    def test_name_with_special_characters(self):
        """Test channel name with special characters."""
        assert sanitize_channel_name("Test@Channel#123!") == "testchannel123"

    def test_name_with_underscores(self):
        """Test channel name with underscores."""
        assert sanitize_channel_name("Test_Channel_Name") == "test-channel-name"

    def test_empty_name(self):
        """Test empty channel name returns default."""
        assert sanitize_channel_name("") == "unknown-channel"

    def test_none_name(self):
        """Test None channel name returns default."""
        assert sanitize_channel_name(None) == "unknown-channel"

    def test_name_with_only_special_chars(self):
        """Test name with only special characters returns default."""
        assert sanitize_channel_name("@#$%^&*") == "unknown-channel"

    def test_consecutive_hyphens(self):
        """Test that consecutive hyphens are collapsed."""
        assert sanitize_channel_name("Test   Channel") == "test-channel"

    def test_leading_trailing_hyphens(self):
        """Test that leading/trailing hyphens are removed."""
        assert sanitize_channel_name("  Test Channel  ") == "test-channel"

    def test_long_name_truncated(self):
        """Test that long names are truncated to 63 characters."""
        long_name = "A" * 100
        result = sanitize_channel_name(long_name)
        assert len(result) <= 63

    def test_unicode_characters_removed(self):
        """Test that unicode characters are removed."""
        assert sanitize_channel_name("Téster Chännél") == "tster-chnnl"


class TestGetTranscriptBlobPath:
    """Tests for get_transcript_blob_path function."""

    def test_basic_path(self):
        """Test basic path generation."""
        result = get_transcript_blob_path("Test Channel", "dQw4w9WgXcQ")
        assert result == "test-channel/dQw4w9WgXcQ/transcript.txt"

    def test_preserves_youtube_id(self):
        """Test that YouTube video ID is preserved exactly."""
        result = get_transcript_blob_path("Channel", "ABC123xyz")
        assert result == "channel/ABC123xyz/transcript.txt"

    def test_sanitizes_channel_name(self):
        """Test that channel name is sanitized in path."""
        result = get_transcript_blob_path("My @#$ Channel!", "video123")
        assert result == "my-channel/video123/transcript.txt"


class TestGetVideoFolderPath:
    """Tests for canonical self-contained video folder paths."""

    def test_basic_folder_path(self):
        """Test canonical folder path generation."""
        result = get_video_folder_path("Mark Wildman", "abc123")
        assert result == "mark-wildman/abc123"


class TestGetSegmentsBlobPath:
    """Tests for get_segments_blob_path function."""

    def test_basic_path(self):
        """Test basic path generation."""
        result = get_segments_blob_path("Test Channel", "dQw4w9WgXcQ")
        assert result == "test-channel/dQw4w9WgXcQ/segments.json"

    def test_preserves_youtube_id(self):
        """Test that YouTube video ID is preserved exactly."""
        result = get_segments_blob_path("Channel", "ABC123xyz")
        assert result == "channel/ABC123xyz/segments.json"


class TestGetSummaryBlobPath:
    """Tests for get_summary_blob_path function."""

    def test_basic_path(self):
        """Test basic summary path generation."""
        result = get_summary_blob_path("Test Channel", "dQw4w9WgXcQ")
        assert result == "test-channel/dQw4w9WgXcQ/summary.md"


class TestGetMetadataBlobPath:
    """Tests for get_metadata_blob_path function."""

    def test_basic_path(self):
        """Test basic metadata path generation."""
        result = get_metadata_blob_path("Test Channel", "dQw4w9WgXcQ")
        assert result == "test-channel/dQw4w9WgXcQ/metadata.json"


class TestExtractBlobNameFromUri:
    """Tests for extracting blob names from stored artifact URIs."""

    def test_preserves_nested_blob_prefix(self):
        """Test that nested video ID prefixes are preserved."""
        blob_uri = (
            "https://account.blob.core.windows.net/summaries/"
            "87af0899-c22d-4a54-9c01-bd2c3de59df7/video_summary.md"
        )

        result = extract_blob_name_from_uri(blob_uri, SUMMARIES_CONTAINER)

        assert result == "87af0899-c22d-4a54-9c01-bd2c3de59df7/video_summary.md"

    def test_falls_back_to_filename_for_simple_value(self):
        """Test fallback behavior for legacy simple blob names."""
        assert extract_blob_name_from_uri("video_summary.md", SUMMARIES_CONTAINER) == (
            "video_summary.md"
        )

    def test_extracts_library_blob_path(self):
        """Test extracting canonical library blob paths."""
        blob_uri = (
            "https://account.blob.core.windows.net/library/mark-wildman/dQw4w9WgXcQ/transcript.txt"
        )

        result = extract_blob_name_from_uri(blob_uri, LIBRARY_CONTAINER)

        assert result == "mark-wildman/dQw4w9WgXcQ/transcript.txt"


class TestBlobClientDownload:
    """Tests for blob download retry behavior."""

    def test_download_blob_does_not_retry_missing_blob(self):
        """Missing blobs should fail quickly instead of retrying slow 404s."""
        blob_client = MagicMock()
        blob_client.download_blob.side_effect = ResourceNotFoundError("missing")
        service_client = MagicMock()
        service_client.get_blob_client.return_value = blob_client

        client = BlobClient()
        client._client = service_client

        with pytest.raises(ResourceNotFoundError):
            client.download_blob("summaries", "missing.md")

        blob_client.download_blob.assert_called_once()
