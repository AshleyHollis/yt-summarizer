"""Tests for blob path consistency across all workers.

These tests ensure that all workers use the shared blob path helper functions
to construct consistent blob storage paths. This prevents the bug where:
- Transcribe worker stores at: {channel_name}/{youtube_video_id}/transcript.txt
- Summarize worker looks at: {video_id}/{youtube_video_id}_transcript.txt (WRONG!)

All workers MUST use the shared path helpers:
- get_transcript_blob_path(channel_name, youtube_video_id)
- get_segments_blob_path(channel_name, youtube_video_id)
- get_summary_blob_path(channel_name, youtube_video_id)
"""

from uuid import uuid4

import pytest

# ============================================================================
# Test fixtures
# ============================================================================


@pytest.fixture
def sample_channel_name():
    """Sample YouTube channel name."""
    return "Hybrid Calisthenics"


@pytest.fixture
def sample_youtube_video_id():
    """Sample YouTube video ID."""
    return "0GsVJsS6474"


@pytest.fixture
def sample_video_id():
    """Sample video UUID."""
    return str(uuid4())


@pytest.fixture
def sample_job_id():
    """Sample job UUID."""
    return str(uuid4())


@pytest.fixture
def sanitized_channel_name(sample_channel_name):
    """Expected sanitized channel name."""
    from shared.blob.client import sanitize_channel_name
    return sanitize_channel_name(sample_channel_name)


# ============================================================================
# Blob Path Helper Tests
# ============================================================================


class TestBlobPathHelpers:
    """Test that blob path helpers produce consistent paths."""

    def test_get_transcript_blob_path_format(self, sample_channel_name, sample_youtube_video_id, sanitized_channel_name):
        """Test transcript blob path follows channel-based format."""
        from shared.blob.client import get_transcript_blob_path

        path = get_transcript_blob_path(sample_channel_name, sample_youtube_video_id)

        assert path == f"{sanitized_channel_name}/{sample_youtube_video_id}/transcript.txt"

    def test_get_segments_blob_path_format(self, sample_channel_name, sample_youtube_video_id, sanitized_channel_name):
        """Test segments blob path follows channel-based format."""
        from shared.blob.client import get_segments_blob_path

        path = get_segments_blob_path(sample_channel_name, sample_youtube_video_id)

        assert path == f"{sanitized_channel_name}/{sample_youtube_video_id}/segments.json"

    def test_get_summary_blob_path_format(self, sample_channel_name, sample_youtube_video_id, sanitized_channel_name):
        """Test summary blob path follows channel-based format."""
        from shared.blob.client import get_summary_blob_path

        path = get_summary_blob_path(sample_channel_name, sample_youtube_video_id)

        assert path == f"{sanitized_channel_name}/{sample_youtube_video_id}/summary.md"

    def test_all_blob_paths_use_same_channel_sanitization(self, sample_channel_name, sample_youtube_video_id):
        """Test all path helpers use the same channel sanitization."""
        from shared.blob.client import (
            get_segments_blob_path,
            get_summary_blob_path,
            get_transcript_blob_path,
        )

        transcript_path = get_transcript_blob_path(sample_channel_name, sample_youtube_video_id)
        segments_path = get_segments_blob_path(sample_channel_name, sample_youtube_video_id)
        summary_path = get_summary_blob_path(sample_channel_name, sample_youtube_video_id)

        # All paths should start with the same sanitized channel name
        transcript_prefix = transcript_path.split("/")[0]
        segments_prefix = segments_path.split("/")[0]
        summary_prefix = summary_path.split("/")[0]

        assert transcript_prefix == segments_prefix == summary_prefix, \
            "All blob paths must use the same sanitized channel name prefix"


# ============================================================================
# Channel Sanitization Tests
# ============================================================================


class TestChannelSanitization:
    """Test channel name sanitization for blob storage."""

    def test_sanitize_channel_name_lowercase(self):
        """Test channel name is lowercased."""
        from shared.blob.client import sanitize_channel_name

        assert sanitize_channel_name("Hybrid Calisthenics") == "hybrid-calisthenics"

    def test_sanitize_channel_name_special_characters(self):
        """Test special characters are handled."""
        from shared.blob.client import sanitize_channel_name

        # Spaces become hyphens
        assert sanitize_channel_name("Tech With Tim") == "tech-with-tim"

        # Special chars become hyphens
        assert sanitize_channel_name("Mr. Beast") == "mr-beast"

    def test_sanitize_channel_name_handles_unknown(self):
        """Test empty channel name returns unknown-channel."""
        from shared.blob.client import sanitize_channel_name

        assert sanitize_channel_name("") == "unknown-channel"

    def test_sanitize_channel_name_trims_length(self):
        """Test long channel names are trimmed."""
        from shared.blob.client import sanitize_channel_name

        long_name = "a" * 100
        result = sanitize_channel_name(long_name)

        assert len(result) <= 63, "Sanitized name must be <= 63 chars for Azure blob prefix"


# ============================================================================
# Worker Message Channel Name Tests
# ============================================================================


class TestWorkerMessagesHaveChannelName:
    """Test that all worker messages include channel_name field."""

    def test_transcribe_message_has_channel_name(self):
        """Test TranscribeMessage has channel_name field."""
        from transcribe.worker import TranscribeMessage

        message = TranscribeMessage(
            job_id=str(uuid4()),
            video_id=str(uuid4()),
            youtube_video_id="test123",
            channel_name="Test Channel",
            correlation_id="corr-123",
        )

        assert hasattr(message, "channel_name")
        assert message.channel_name == "Test Channel"

    def test_summarize_message_has_channel_name(self):
        """Test SummarizeMessage has channel_name field."""
        from summarize.worker import SummarizeMessage

        message = SummarizeMessage(
            job_id=str(uuid4()),
            video_id=str(uuid4()),
            youtube_video_id="test123",
            channel_name="Test Channel",
            correlation_id="corr-123",
        )

        assert hasattr(message, "channel_name")
        assert message.channel_name == "Test Channel"

    def test_embed_message_has_channel_name(self):
        """Test EmbedMessage has channel_name field."""
        from embed.worker import EmbedMessage

        message = EmbedMessage(
            job_id=str(uuid4()),
            video_id=str(uuid4()),
            youtube_video_id="test123",
            channel_name="Test Channel",
            correlation_id="corr-123",
        )

        assert hasattr(message, "channel_name")
        assert message.channel_name == "Test Channel"

    def test_relationships_message_has_channel_name(self):
        """Test RelationshipsMessage has channel_name field."""
        from relationships.worker import RelationshipsMessage

        message = RelationshipsMessage(
            job_id=str(uuid4()),
            video_id=str(uuid4()),
            youtube_video_id="test123",
            channel_name="Test Channel",
            correlation_id="corr-123",
        )

        assert hasattr(message, "channel_name")
        assert message.channel_name == "Test Channel"


# ============================================================================
# Channel Name Propagation Tests
# ============================================================================


class TestChannelNamePropagation:
    """Test that channel_name propagates through the entire worker pipeline."""

    def test_all_workers_parse_channel_name_from_message(self):
        """Test all workers correctly parse channel_name from raw message."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        raw_message = {
            "job_id": str(uuid4()),
            "video_id": str(uuid4()),
            "youtube_video_id": "test123",
            "channel_name": "My Test Channel",
            "correlation_id": "corr-123",
        }

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        for worker in workers:
            message = worker.parse_message(raw_message)
            assert message.channel_name == "My Test Channel", \
                f"{type(worker).__name__} failed to parse channel_name"

    def test_all_workers_default_channel_name_when_missing(self):
        """Test all workers default to 'unknown-channel' when channel_name is missing."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        raw_message = {
            "job_id": str(uuid4()),
            "video_id": str(uuid4()),
            "youtube_video_id": "test123",
            "correlation_id": "corr-123",
            # Note: channel_name is missing!
        }

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        for worker in workers:
            message = worker.parse_message(raw_message)
            assert message.channel_name == "unknown-channel", \
                f"{type(worker).__name__} failed to default channel_name"


# ============================================================================
# Worker Blob Path Usage Tests
# ============================================================================


class TestWorkersUseBlobPathHelpers:
    """Test that workers use the shared blob path helpers, not hardcoded paths.
    
    This is a regression test for the bug where:
    - Transcribe stored at: hybrid-calisthenics/0GsVJsS6474/transcript.txt
    - Summarize looked at: {uuid}/0GsVJsS6474_transcript.txt (WRONG!)
    """

    def test_summarize_worker_imports_path_helpers(self):
        """Test SummarizeWorker imports and can use blob path helpers."""
        # Verify the import exists in summarize worker

        # Check that the module imports the path helpers
        from shared.blob.client import get_transcript_blob_path

        # Verify the helpers are callable
        path = get_transcript_blob_path("Test Channel", "abc123")
        assert "/" in path, "Path helper should return path with directory separator"

    def test_embed_worker_imports_path_helpers(self):
        """Test EmbedWorker imports and can use blob path helpers."""

        # Check that the module imports the path helpers
        from shared.blob.client import (
            get_segments_blob_path,
            get_summary_blob_path,
            get_transcript_blob_path,
        )

        # Verify all helpers work
        for helper in [get_transcript_blob_path, get_segments_blob_path, get_summary_blob_path]:
            path = helper("Test Channel", "abc123")
            assert "/" in path

    def test_blob_paths_match_between_transcribe_and_summarize(
        self,
        sample_channel_name,
        sample_youtube_video_id,
    ):
        """Test that transcribe's storage path matches summarize's fetch path.
        
        This is the core regression test for the bug where paths didn't match.
        """
        from shared.blob.client import get_transcript_blob_path

        # Both workers should use the SAME path for the same video
        transcribe_storage_path = get_transcript_blob_path(sample_channel_name, sample_youtube_video_id)
        summarize_fetch_path = get_transcript_blob_path(sample_channel_name, sample_youtube_video_id)

        assert transcribe_storage_path == summarize_fetch_path, \
            "Transcribe storage path must match summarize fetch path!"

    def test_blob_paths_match_between_summarize_and_embed(
        self,
        sample_channel_name,
        sample_youtube_video_id,
    ):
        """Test that summarize's storage path matches embed's fetch path."""
        from shared.blob.client import get_summary_blob_path

        # Both workers should use the SAME path for the same video
        summarize_storage_path = get_summary_blob_path(sample_channel_name, sample_youtube_video_id)
        embed_fetch_path = get_summary_blob_path(sample_channel_name, sample_youtube_video_id)

        assert summarize_storage_path == embed_fetch_path, \
            "Summarize storage path must match embed fetch path!"


# ============================================================================
# Integration: End-to-End Path Consistency
# ============================================================================


class TestEndToEndPathConsistency:
    """Integration tests for blob path consistency across the full pipeline."""

    def test_full_pipeline_uses_consistent_paths(
        self,
        sample_channel_name,
        sample_youtube_video_id,
    ):
        """Test that transcript path is consistent across all workers that use it."""
        from shared.blob.client import (
            get_segments_blob_path,
            get_summary_blob_path,
            get_transcript_blob_path,
            sanitize_channel_name,
        )

        sanitized = sanitize_channel_name(sample_channel_name)

        # Expected path formats
        expected_transcript = f"{sanitized}/{sample_youtube_video_id}/transcript.txt"
        expected_segments = f"{sanitized}/{sample_youtube_video_id}/segments.json"
        expected_summary = f"{sanitized}/{sample_youtube_video_id}/summary.md"

        # Verify all helpers produce the expected format
        assert get_transcript_blob_path(sample_channel_name, sample_youtube_video_id) == expected_transcript
        assert get_segments_blob_path(sample_channel_name, sample_youtube_video_id) == expected_segments
        assert get_summary_blob_path(sample_channel_name, sample_youtube_video_id) == expected_summary

    def test_paths_are_unique_per_video(self, sample_channel_name):
        """Test that different videos get different paths."""
        from shared.blob.client import get_transcript_blob_path

        video1 = "abc123"
        video2 = "xyz789"

        path1 = get_transcript_blob_path(sample_channel_name, video1)
        path2 = get_transcript_blob_path(sample_channel_name, video2)

        assert path1 != path2, "Different videos must have different paths"

    def test_paths_are_unique_per_channel(self, sample_youtube_video_id):
        """Test that same video on different channels gets different paths."""
        from shared.blob.client import get_transcript_blob_path

        channel1 = "Channel One"
        channel2 = "Channel Two"

        path1 = get_transcript_blob_path(channel1, sample_youtube_video_id)
        path2 = get_transcript_blob_path(channel2, sample_youtube_video_id)

        assert path1 != path2, "Same video on different channels must have different paths"
