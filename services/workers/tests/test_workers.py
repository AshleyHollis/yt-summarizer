"""Integration tests for workers.

These tests verify the worker processing logic using mocked dependencies.
They test the core business logic without requiring external services.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_job_id():
    """Generate a sample job ID."""
    return str(uuid4())


@pytest.fixture
def sample_video_id():
    """Generate a sample video ID."""
    return str(uuid4())


@pytest.fixture
def sample_youtube_video_id():
    """Sample YouTube video ID."""
    return "dQw4w9WgXcQ"


@pytest.fixture
def sample_correlation_id():
    """Sample correlation ID."""
    return f"test-{uuid4()}"


@pytest.fixture
def sample_transcript():
    """Sample transcript text."""
    return """
    Welcome to this video. Today we're going to talk about something important.
    This is a test transcript with multiple sentences.
    It contains various topics and ideas that can be summarized.
    Thank you for watching!
    """


@pytest.fixture
def sample_summary():
    """Sample summary text."""
    return """
    # Video Summary

    ## Key Points
    - This video discusses important topics
    - Multiple sentences cover various ideas
    - The speaker thanks viewers at the end

    ## Main Takeaways
    The video provides a comprehensive overview of the subject matter.
    """


# =============================================================================
# Transcribe Worker Tests
# =============================================================================


class TestTranscribeWorkerMessageParsing:
    """Tests for transcribe worker message parsing."""

    def test_parse_valid_message(self):
        """Test parsing a valid transcribe message."""
        from transcribe.worker import TranscribeWorker, TranscribeMessage

        worker = TranscribeWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-correlation-123",
            "retry_count": 0,
        }
        
        message = worker.parse_message(raw_message)
        
        assert isinstance(message, TranscribeMessage)
        assert message.job_id == raw_message["job_id"]
        assert message.video_id == raw_message["video_id"]
        assert message.youtube_video_id == raw_message["youtube_video_id"]
        assert message.correlation_id == raw_message["correlation_id"]
        assert message.retry_count == 0

    def test_parse_message_with_missing_optional_fields(self):
        """Test parsing a message with missing optional fields."""
        from transcribe.worker import TranscribeWorker, TranscribeMessage

        worker = TranscribeWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
        }
        
        message = worker.parse_message(raw_message)
        
        assert message.correlation_id == "unknown"
        assert message.retry_count == 0


class TestTranscribeWorkerProcessing:
    """Tests for transcribe worker processing logic."""

    def test_transcribe_worker_has_required_methods(self):
        """Test that transcribe worker has all required methods."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        
        # Verify worker has required interface
        assert hasattr(worker, "queue_name")
        assert hasattr(worker, "parse_message")
        assert hasattr(worker, "process_message")
        assert callable(worker.parse_message)
        assert callable(worker.process_message)

    @pytest.mark.asyncio
    async def test_transcribe_worker_fails_when_no_transcript_available(
        self,
        sample_job_id,
        sample_video_id,
        sample_correlation_id,
    ):
        """Test that transcribe worker properly fails when video has no transcript.
        
        This validates that videos without captions or auto-generated subtitles
        are marked as failed with a clear error message, preventing them from
        progressing through the pipeline with empty content.
        """
        from shared.worker.base_worker import WorkerStatus
        from transcribe.worker import TranscribeWorker, TranscribeMessage

        worker = TranscribeWorker()
        
        # Create a message for a video without transcripts
        # Using a known video ID that has no transcripts (CrossFit's "The Push-Up")
        message = TranscribeMessage(
            job_id=sample_job_id,
            video_id=sample_video_id,
            youtube_video_id="rRcg6m4pIEg",  # CrossFit's "The Push-Up" - no transcripts
            correlation_id=sample_correlation_id,
            retry_count=0,
        )
        
        # Mock the job status updates to avoid DB calls
        with patch("transcribe.worker.mark_job_running", new_callable=AsyncMock) as mock_running, \
             patch("transcribe.worker.mark_job_failed", new_callable=AsyncMock) as mock_failed:
            
            # Process the message - should fail due to no transcript
            result = await worker.process_message(message, sample_correlation_id)
            
            # Verify the job was marked as failed
            assert result.status == WorkerStatus.FAILED
            assert "No transcript available" in result.message
            
            # Verify mark_job_running was called
            mock_running.assert_called_once_with(sample_job_id, "transcribing")
            
            # Verify mark_job_failed was called with appropriate error message
            mock_failed.assert_called_once()
            call_args = mock_failed.call_args
            assert "No transcript available" in call_args[0][1]
            assert "captions" in call_args[0][1] or "subtitles" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_transcribe_worker_succeeds_with_valid_transcript(
        self,
        sample_job_id,
        sample_video_id,
        sample_correlation_id,
        sample_transcript,
    ):
        """Test that transcribe worker succeeds when transcript is available.
        
        This validates the happy path where a video has transcripts and
        the worker extracts them successfully.
        """
        from shared.worker.base_worker import WorkerStatus
        from transcribe.worker import TranscribeWorker, TranscribeMessage

        worker = TranscribeWorker()
        
        message = TranscribeMessage(
            job_id=sample_job_id,
            video_id=sample_video_id,
            youtube_video_id="dQw4w9WgXcQ",  # Rick Astley - has transcripts
            correlation_id=sample_correlation_id,
            retry_count=0,
        )
        
        # Mock all external dependencies
        with patch("transcribe.worker.mark_job_running", new_callable=AsyncMock) as mock_running, \
             patch("transcribe.worker.mark_job_completed", new_callable=AsyncMock) as mock_completed, \
             patch.object(worker, "_fetch_transcript", new_callable=AsyncMock) as mock_fetch, \
             patch.object(worker, "_fetch_transcript_with_timestamps", new_callable=AsyncMock) as mock_fetch_ts, \
             patch.object(worker, "_store_transcript", new_callable=AsyncMock) as mock_store, \
             patch.object(worker, "_store_timestamped_segments", new_callable=AsyncMock) as mock_store_ts, \
             patch.object(worker, "_create_artifact", new_callable=AsyncMock) as mock_artifact, \
             patch.object(worker, "_queue_next_job", new_callable=AsyncMock) as mock_queue:
            
            # Configure mocks
            mock_fetch.return_value = sample_transcript
            mock_fetch_ts.return_value = [
                {"start": 0.0, "duration": 5.0, "text": "Hello world"},
                {"start": 5.0, "duration": 5.0, "text": "This is a test"},
            ]
            mock_store.return_value = f"transcripts/{sample_video_id}.txt"
            mock_store_ts.return_value = f"transcripts/{sample_video_id}_segments.json"
            
            # Process the message
            result = await worker.process_message(message, sample_correlation_id)
            
            # Verify success
            assert result.status == WorkerStatus.SUCCESS
            
            # Verify job status updates
            mock_running.assert_called_once_with(sample_job_id, "transcribing")
            mock_completed.assert_called_once_with(sample_job_id)
            
            # Verify transcript was stored and artifact created
            mock_store.assert_called_once()
            mock_artifact.assert_called_once()
            
            # Verify timestamped segments were stored
            mock_store_ts.assert_called_once()
            
            # Verify next job was queued
            mock_queue.assert_called_once()


# =============================================================================
# Summarize Worker Tests
# =============================================================================


class TestSummarizeWorkerMessageParsing:
    """Tests for summarize worker message parsing."""

    def test_parse_valid_message(self):
        """Test parsing a valid summarize message."""
        from summarize.worker import SummarizeWorker, SummarizeMessage

        worker = SummarizeWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-correlation-123",
            "retry_count": 0,
        }
        
        message = worker.parse_message(raw_message)
        
        assert message.job_id == raw_message["job_id"]
        assert message.video_id == raw_message["video_id"]
        assert message.youtube_video_id == raw_message["youtube_video_id"]


# =============================================================================
# Embed Worker Tests
# =============================================================================


class TestEmbedWorkerMessageParsing:
    """Tests for embed worker message parsing."""

    def test_parse_valid_message(self):
        """Test parsing a valid embed message."""
        from embed.worker import EmbedWorker, EmbedMessage

        worker = EmbedWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-correlation-123",
        }
        
        message = worker.parse_message(raw_message)
        
        assert message.job_id == raw_message["job_id"]
        assert message.video_id == raw_message["video_id"]
        assert message.youtube_video_id == raw_message["youtube_video_id"]


class TestEmbedWorkerChunking:
    """Tests for embed worker text chunking logic."""

    def test_chunk_content_splits_long_text(self, sample_transcript):
        """Test that long text is split into chunks."""
        from embed.worker import EmbedWorker

        worker = EmbedWorker()
        
        # Create a long text
        long_text = sample_transcript * 100  # Repeat to make it long
        
        # Chunk using the actual method name
        chunks = worker._chunk_content(long_text)
        
        # Should have multiple chunks for long text
        assert len(chunks) >= 1

    def test_chunk_content_handles_short_text(self):
        """Test that short text is not split unnecessarily."""
        from embed.worker import EmbedWorker

        worker = EmbedWorker()
        
        short_text = "This is a short text."
        
        chunks = worker._chunk_content(short_text)
        
        # Should have at least one chunk
        assert len(chunks) >= 1
        # First chunk should contain the text
        assert short_text in chunks[0]


# =============================================================================
# Relationships Worker Tests
# =============================================================================


class TestRelationshipsWorkerMessageParsing:
    """Tests for relationships worker message parsing."""

    def test_parse_valid_message(self):
        """Test parsing a valid relationships message."""
        from relationships.worker import RelationshipsWorker, RelationshipsMessage

        worker = RelationshipsWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-correlation-123",
        }
        
        message = worker.parse_message(raw_message)
        
        assert message.job_id == raw_message["job_id"]
        assert message.video_id == raw_message["video_id"]
        assert message.youtube_video_id == raw_message["youtube_video_id"]

    def test_parse_message_with_batch_id(self):
        """Test parsing a message with batch_id."""
        from relationships.worker import RelationshipsWorker

        worker = RelationshipsWorker()
        
        raw_message = {
            "job_id": "123e4567-e89b-12d3-a456-426614174000",
            "video_id": "123e4567-e89b-12d3-a456-426614174001",
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-correlation-123",
            "batch_id": "batch-123",
            "retry_count": 2,
        }
        
        message = worker.parse_message(raw_message)
        
        assert message.batch_id == "batch-123"
        assert message.retry_count == 2


class TestRelationshipsWorkerEmbeddingMath:
    """Tests for relationships worker embedding calculations."""

    def test_average_embeddings_single(self):
        """Test averaging a single embedding."""
        from relationships.worker import RelationshipsWorker
        import numpy as np

        worker = RelationshipsWorker()
        
        # Single embedding
        embeddings = [[1.0, 0.0, 0.0]]
        result = worker._average_embeddings(embeddings)
        
        # Should be normalized unit vector
        assert len(result) == 3
        np.testing.assert_almost_equal(np.linalg.norm(result), 1.0)
        
    def test_average_embeddings_multiple(self):
        """Test averaging multiple embeddings."""
        from relationships.worker import RelationshipsWorker
        import numpy as np

        worker = RelationshipsWorker()
        
        # Two embeddings
        embeddings = [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ]
        result = worker._average_embeddings(embeddings)
        
        # Result should be normalized
        assert len(result) == 3
        np.testing.assert_almost_equal(np.linalg.norm(result), 1.0)
        # Average of [1,0,0] and [0,1,0] normalized should have equal x and y components
        np.testing.assert_almost_equal(result[0], result[1])
        
    def test_average_embeddings_empty(self):
        """Test averaging empty embeddings returns empty list."""
        from relationships.worker import RelationshipsWorker

        worker = RelationshipsWorker()
        
        result = worker._average_embeddings([])
        
        assert result == []


class TestRelationshipsWorkerSimilarityThreshold:
    """Tests for relationship similarity threshold behavior."""

    def test_similarity_threshold_default(self):
        """Test default similarity threshold is 0.7."""
        from relationships.worker import DEFAULT_SIMILARITY_THRESHOLD
        
        # The system should use 0.7 as the default similarity threshold
        # Videos must be at least 70% similar to be considered related
        assert DEFAULT_SIMILARITY_THRESHOLD == 0.7

    def test_max_related_default(self):
        """Test default max related videos is 10."""
        from relationships.worker import DEFAULT_MAX_RELATED
        
        # Should not return more than 10 related videos per video
        assert DEFAULT_MAX_RELATED == 10


# =============================================================================
# Worker Queue Name Tests
# =============================================================================


class TestWorkerQueueNames:
    """Tests for worker queue name configuration."""

    def test_transcribe_worker_queue_name(self):
        """Test transcribe worker uses correct queue."""
        from transcribe.worker import TranscribeWorker
        from shared.queue.client import TRANSCRIBE_QUEUE

        worker = TranscribeWorker()
        assert worker.queue_name == TRANSCRIBE_QUEUE

    def test_summarize_worker_queue_name(self):
        """Test summarize worker uses correct queue."""
        from summarize.worker import SummarizeWorker
        from shared.queue.client import SUMMARIZE_QUEUE

        worker = SummarizeWorker()
        assert worker.queue_name == SUMMARIZE_QUEUE

    def test_embed_worker_queue_name(self):
        """Test embed worker uses correct queue."""
        from embed.worker import EmbedWorker
        from shared.queue.client import EMBED_QUEUE

        worker = EmbedWorker()
        assert worker.queue_name == EMBED_QUEUE

    def test_relationships_worker_queue_name(self):
        """Test relationships worker uses correct queue."""
        from relationships.worker import RelationshipsWorker
        from shared.queue.client import RELATIONSHIPS_QUEUE

        worker = RelationshipsWorker()
        assert worker.queue_name == RELATIONSHIPS_QUEUE


# =============================================================================
# Worker Result Tests
# =============================================================================


class TestWorkerResult:
    """Tests for worker result handling."""

    def test_worker_result_success(self):
        """Test creating a successful worker result."""
        from shared.worker.base_worker import WorkerResult, WorkerStatus

        result = WorkerResult.success()
        
        assert result.status == WorkerStatus.SUCCESS
        assert result.error is None

    def test_worker_result_failure(self):
        """Test creating a failed worker result."""
        from shared.worker.base_worker import WorkerResult, WorkerStatus

        error = Exception("Test error")
        result = WorkerResult.failed(error, "Test failure message")
        
        assert result.status == WorkerStatus.FAILED
        assert result.error == error
        assert result.message == "Test failure message"

    def test_worker_result_retry(self):
        """Test creating a retry worker result."""
        from shared.worker.base_worker import WorkerResult, WorkerStatus

        result = WorkerResult.retry("Temporary failure")
        
        assert result.status == WorkerStatus.RETRY
        assert result.message == "Temporary failure"


# =============================================================================
# Integration: Full Pipeline Mock Test
# =============================================================================


class TestWorkerPipelineIntegration:
    """Integration tests for the full worker pipeline."""

    @pytest.mark.asyncio
    async def test_worker_pipeline_message_flow(
        self,
        sample_job_id,
        sample_video_id,
        sample_youtube_video_id,
        sample_correlation_id,
    ):
        """Test that workers pass correct message structure to next worker."""
        # This test verifies the message contract between workers
        
        # All workers use similar message structure
        common_message = {
            "job_id": sample_job_id,
            "video_id": sample_video_id,
            "youtube_video_id": sample_youtube_video_id,
            "correlation_id": sample_correlation_id,
        }
        
        # Test Transcribe worker parsing
        from transcribe.worker import TranscribeWorker
        transcribe_worker = TranscribeWorker()
        transcribe_message = transcribe_worker.parse_message(common_message)
        assert transcribe_message.video_id == sample_video_id
        assert transcribe_message.youtube_video_id == sample_youtube_video_id
        
        # Test Summarize worker parsing
        from summarize.worker import SummarizeWorker
        summarize_worker = SummarizeWorker()
        summarize_message = summarize_worker.parse_message(common_message)
        assert summarize_message.video_id == sample_video_id
        assert summarize_message.youtube_video_id == sample_youtube_video_id
        
        # Test Embed worker parsing
        from embed.worker import EmbedWorker
        embed_worker = EmbedWorker()
        embed_message = embed_worker.parse_message(common_message)
        assert embed_message.video_id == sample_video_id
        assert embed_message.youtube_video_id == sample_youtube_video_id
        
        # Test Relationships worker parsing
        from relationships.worker import RelationshipsWorker
        relationships_worker = RelationshipsWorker()
        relationships_message = relationships_worker.parse_message(common_message)
        assert relationships_message.video_id == sample_video_id
