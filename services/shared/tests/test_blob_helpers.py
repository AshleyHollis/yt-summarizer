"""Tests for blob storage helper functions."""

import pytest

from shared.blob.client import (
    get_segments_blob_path,
    get_transcript_blob_path,
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
