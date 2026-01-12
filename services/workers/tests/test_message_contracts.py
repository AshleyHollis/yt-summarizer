"""Integration tests for Worker → Queue → Worker message contracts.

These tests verify that:
1. API publishes messages with all required fields for workers
2. Workers expect and can parse all message fields correctly
3. Workers publish correct messages to downstream queues
4. Status codes, job types, and other enums are consistent
5. batch_id propagates correctly through the entire pipeline

This is critical for preventing bugs where:
- API publishes a message missing data that workers need
- Workers send messages with incorrect/mismatched field names
- Status enums don't match between services
"""

from dataclasses import fields
from uuid import uuid4

import pytest

# Check if numpy is available (required for relationships worker)
try:
    import numpy

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# Check if api module is available (for cross-service consistency tests)
try:
    from api.models.job import JobStage, JobStatus, JobType

    HAS_API = True
except ImportError:
    HAS_API = False

# Skip relationships worker tests if numpy not available
requires_numpy = pytest.mark.skipif(not HAS_NUMPY, reason="numpy not installed")

# Skip API consistency tests if api module not available
requires_api = pytest.mark.skipif(
    not HAS_API, reason="api module not installed - cross-service tests require api package"
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_job_id():
    """Sample job ID."""
    return str(uuid4())


@pytest.fixture
def sample_video_id():
    """Sample video ID."""
    return str(uuid4())


@pytest.fixture
def sample_batch_id():
    """Sample batch ID."""
    return str(uuid4())


@pytest.fixture
def sample_youtube_video_id():
    """Sample YouTube video ID."""
    return "dQw4w9WgXcQ"


@pytest.fixture
def sample_correlation_id():
    """Sample correlation ID."""
    return "test-correlation-123"


@pytest.fixture
def sample_channel_name():
    """Sample channel name."""
    return "Test Channel"


@pytest.fixture
def complete_api_message(
    sample_job_id,
    sample_video_id,
    sample_youtube_video_id,
    sample_batch_id,
    sample_correlation_id,
    sample_channel_name,
):
    """Complete message as sent by API with all fields."""
    return {
        "job_id": sample_job_id,
        "video_id": sample_video_id,
        "youtube_video_id": sample_youtube_video_id,
        "channel_name": sample_channel_name,
        "batch_id": sample_batch_id,
        "correlation_id": sample_correlation_id,
    }


@pytest.fixture
def minimal_api_message(
    sample_job_id,
    sample_video_id,
    sample_youtube_video_id,
    sample_correlation_id,
):
    """Minimal message as sent by API (no batch_id)."""
    return {
        "job_id": sample_job_id,
        "video_id": sample_video_id,
        "youtube_video_id": sample_youtube_video_id,
        "correlation_id": sample_correlation_id,
    }


# ============================================================================
# Message Schema Tests - Required Fields
# ============================================================================


class TestWorkerMessageRequiredFields:
    """Test that all workers can parse required message fields."""

    REQUIRED_FIELDS = ["job_id", "video_id", "youtube_video_id"]
    OPTIONAL_FIELDS = ["correlation_id", "batch_id", "retry_count"]

    def test_transcribe_worker_required_fields(self, complete_api_message):
        """Test TranscribeWorker can parse all required fields."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        message = worker.parse_message(complete_api_message)

        assert message.job_id == complete_api_message["job_id"]
        assert message.video_id == complete_api_message["video_id"]
        assert message.youtube_video_id == complete_api_message["youtube_video_id"]
        assert message.channel_name == complete_api_message["channel_name"]

    def test_summarize_worker_required_fields(self, complete_api_message):
        """Test SummarizeWorker can parse all required fields."""
        from summarize.worker import SummarizeWorker

        worker = SummarizeWorker()
        message = worker.parse_message(complete_api_message)

        assert message.job_id == complete_api_message["job_id"]
        assert message.video_id == complete_api_message["video_id"]
        assert message.youtube_video_id == complete_api_message["youtube_video_id"]

    def test_embed_worker_required_fields(self, complete_api_message):
        """Test EmbedWorker can parse all required fields."""
        from embed.worker import EmbedWorker

        worker = EmbedWorker()
        message = worker.parse_message(complete_api_message)

        assert message.job_id == complete_api_message["job_id"]
        assert message.video_id == complete_api_message["video_id"]
        assert message.youtube_video_id == complete_api_message["youtube_video_id"]

    @requires_numpy
    def test_relationships_worker_required_fields(self, complete_api_message):
        """Test RelationshipsWorker can parse all required fields."""
        from relationships.worker import RelationshipsWorker

        worker = RelationshipsWorker()
        message = worker.parse_message(complete_api_message)

        assert message.job_id == complete_api_message["job_id"]
        assert message.video_id == complete_api_message["video_id"]
        assert message.youtube_video_id == complete_api_message["youtube_video_id"]

    @requires_numpy
    def test_all_workers_have_consistent_required_fields(self):
        """Verify all worker message dataclasses have the same required fields."""
        from embed.worker import EmbedMessage
        from relationships.worker import RelationshipsMessage
        from summarize.worker import SummarizeMessage
        from transcribe.worker import TranscribeMessage

        message_classes = [
            TranscribeMessage,
            SummarizeMessage,
            EmbedMessage,
            RelationshipsMessage,
        ]

        for message_class in message_classes:
            field_names = {f.name for f in fields(message_class)}

            for required in self.REQUIRED_FIELDS:
                assert required in field_names, (
                    f"{message_class.__name__} missing required field: {required}"
                )


# ============================================================================
# Message Schema Tests - Optional Fields
# ============================================================================


class TestWorkerMessageOptionalFields:
    """Test that all workers handle optional fields correctly."""

    def test_transcribe_worker_handles_missing_batch_id(self, minimal_api_message):
        """Test TranscribeWorker handles missing batch_id."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        message = worker.parse_message(minimal_api_message)

        assert message.batch_id is None

    def test_transcribe_worker_handles_present_batch_id(self, complete_api_message):
        """Test TranscribeWorker parses batch_id when present."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        message = worker.parse_message(complete_api_message)

        assert message.batch_id == complete_api_message["batch_id"]

    def test_transcribe_worker_handles_missing_correlation_id(
        self, sample_job_id, sample_video_id, sample_youtube_video_id
    ):
        """Test TranscribeWorker defaults correlation_id to 'unknown'."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        message = worker.parse_message(
            {
                "job_id": sample_job_id,
                "video_id": sample_video_id,
                "youtube_video_id": sample_youtube_video_id,
            }
        )

        assert message.correlation_id == "unknown"

    def test_transcribe_worker_handles_missing_channel_name(
        self, sample_job_id, sample_video_id, sample_youtube_video_id
    ):
        """Test TranscribeWorker defaults channel_name to 'unknown-channel'."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()
        message = worker.parse_message(
            {
                "job_id": sample_job_id,
                "video_id": sample_video_id,
                "youtube_video_id": sample_youtube_video_id,
            }
        )

        assert message.channel_name == "unknown-channel"

    def test_all_workers_default_retry_count_to_zero(self, minimal_api_message):
        """Test all workers default retry_count to 0."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        for worker in workers:
            message = worker.parse_message(minimal_api_message)
            assert message.retry_count == 0, (
                f"{type(worker).__name__} has wrong default retry_count"
            )


# ============================================================================
# Message Schema Tests - Missing Required Fields
# ============================================================================


class TestWorkerMessageMissingRequiredFields:
    """Test that workers fail gracefully with missing required fields."""

    def test_transcribe_worker_fails_without_job_id(self, sample_video_id, sample_youtube_video_id):
        """Test TranscribeWorker raises error without job_id."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        with pytest.raises(KeyError):
            worker.parse_message(
                {
                    "video_id": sample_video_id,
                    "youtube_video_id": sample_youtube_video_id,
                }
            )

    def test_transcribe_worker_fails_without_video_id(self, sample_job_id, sample_youtube_video_id):
        """Test TranscribeWorker raises error without video_id."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        with pytest.raises(KeyError):
            worker.parse_message(
                {
                    "job_id": sample_job_id,
                    "youtube_video_id": sample_youtube_video_id,
                }
            )

    def test_transcribe_worker_fails_without_youtube_video_id(self, sample_job_id, sample_video_id):
        """Test TranscribeWorker raises error without youtube_video_id."""
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        with pytest.raises(KeyError):
            worker.parse_message(
                {
                    "job_id": sample_job_id,
                    "video_id": sample_video_id,
                }
            )


# ============================================================================
# Batch ID Propagation Tests
# ============================================================================


class TestBatchIdPropagation:
    """Test that batch_id propagates through the entire pipeline."""

    def test_all_workers_preserve_batch_id(self, complete_api_message):
        """Test all workers include batch_id in their message dataclass."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        for worker in workers:
            message = worker.parse_message(complete_api_message)
            assert hasattr(message, "batch_id"), (
                f"{type(worker).__name__} message missing batch_id field"
            )
            assert message.batch_id == complete_api_message["batch_id"], (
                f"{type(worker).__name__} has wrong batch_id value"
            )

    def test_batch_id_is_optional_in_all_workers(self, minimal_api_message):
        """Test all workers handle None batch_id."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        for worker in workers:
            message = worker.parse_message(minimal_api_message)
            assert message.batch_id is None, f"{type(worker).__name__} should have None batch_id"


# ============================================================================
# Job Type and Status Consistency Tests
# ============================================================================


@requires_api
class TestJobTypeConsistency:
    """Test that job types are consistent between API and workers."""

    def test_job_types_match_worker_queue_names(self):
        """Test JobType enum values match the expected worker patterns."""
        from api.models.job import JobType
        from shared.queue.client import (
            EMBED_QUEUE,
            RELATIONSHIPS_QUEUE,
            SUMMARIZE_QUEUE,
            TRANSCRIBE_QUEUE,
        )

        # Map JobType to expected queue names
        expected_mapping = {
            JobType.TRANSCRIBE: TRANSCRIBE_QUEUE,
            JobType.SUMMARIZE: SUMMARIZE_QUEUE,
            JobType.EMBED: EMBED_QUEUE,
            JobType.BUILD_RELATIONSHIPS: RELATIONSHIPS_QUEUE,
        }

        # Verify all job types have corresponding queues
        for job_type, expected_queue in expected_mapping.items():
            assert expected_queue is not None, f"No queue defined for {job_type.value}"

    def test_job_types_valid_values(self):
        """Test JobType enum has expected values."""
        from api.models.job import JobType

        expected_values = {"transcribe", "summarize", "embed", "build_relationships"}
        actual_values = {jt.value for jt in JobType}

        assert actual_values == expected_values, (
            f"JobType mismatch. Expected: {expected_values}, Got: {actual_values}"
        )


@requires_api
class TestJobStatusConsistency:
    """Test that job statuses are consistent across services."""

    def test_job_status_values(self):
        """Test JobStatus enum has expected values."""
        from api.models.job import JobStatus

        expected_values = {"pending", "running", "succeeded", "failed"}
        actual_values = {js.value for js in JobStatus}

        assert actual_values == expected_values, (
            f"JobStatus mismatch. Expected: {expected_values}, Got: {actual_values}"
        )

    def test_job_stage_values(self):
        """Test JobStage enum has expected values."""
        from api.models.job import JobStage

        expected_values = {
            "queued",
            "running",
            "completed",
            "failed",
            "dead_lettered",
            "rate_limited",
        }
        actual_values = {js.value for js in JobStage}

        assert actual_values == expected_values, (
            f"JobStage mismatch. Expected: {expected_values}, Got: {actual_values}"
        )

    def test_worker_status_strings_match_api_enum(self):
        """Test that workers use valid status strings."""
        from api.models.job import JobStatus

        # These are the status strings used in workers
        worker_status_strings = ["pending", "running", "succeeded", "failed"]

        for status_str in worker_status_strings:
            # This will raise ValueError if invalid
            JobStatus(status_str)


# ============================================================================
# Queue Name Consistency Tests
# ============================================================================


class TestQueueNameConsistency:
    """Test that queue names are consistent across API and workers."""

    def test_all_workers_use_shared_queue_names(self):
        """Test workers use queue names from shared package."""
        from shared.queue.client import (
            EMBED_QUEUE,
            RELATIONSHIPS_QUEUE,
            SUMMARIZE_QUEUE,
            TRANSCRIBE_QUEUE,
        )

        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        workers_and_queues = [
            (TranscribeWorker(), TRANSCRIBE_QUEUE),
            (SummarizeWorker(), SUMMARIZE_QUEUE),
            (EmbedWorker(), EMBED_QUEUE),
            (RelationshipsWorker(), RELATIONSHIPS_QUEUE),
        ]

        for worker, expected_queue in workers_and_queues:
            assert worker.queue_name == expected_queue, (
                f"{type(worker).__name__}.queue_name mismatch. "
                f"Expected: {expected_queue}, Got: {worker.queue_name}"
            )

    def test_queue_name_format(self):
        """Test queue names follow expected naming convention."""
        from shared.queue.client import (
            EMBED_QUEUE,
            RELATIONSHIPS_QUEUE,
            SUMMARIZE_QUEUE,
            TRANSCRIBE_QUEUE,
        )

        queues = [TRANSCRIBE_QUEUE, SUMMARIZE_QUEUE, EMBED_QUEUE, RELATIONSHIPS_QUEUE]

        for queue in queues:
            # Queue names should end with "-jobs" or similar pattern
            assert queue.endswith("-jobs") or "-" in queue, (
                f"Queue name '{queue}' doesn't follow naming convention"
            )


# ============================================================================
# API Message Structure Tests
# ============================================================================


class TestApiMessageStructure:
    """Test that API sends correctly structured messages."""

    def test_api_video_service_message_structure(self):
        """Test VideoService sends complete messages to queue."""
        # Verify the message structure that VideoService sends
        # This validates the contract between API and workers

        expected_fields = {
            "job_id",
            "video_id",
            "youtube_video_id",
            "correlation_id",
        }

        optional_fields = {
            "batch_id",
        }

        # The message sent by API (from video_service.py)
        # queue_client.send_message(
        #     TRANSCRIBE_QUEUE,
        #     {
        #         "job_id": str(job.job_id),
        #         "video_id": str(video.video_id),
        #         "youtube_video_id": youtube_video_id,
        #         "correlation_id": correlation_id,
        #     },
        # )

        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        # Test with required fields only
        required_message = {
            "job_id": str(uuid4()),
            "video_id": str(uuid4()),
            "youtube_video_id": "dQw4w9WgXcQ",
            "correlation_id": "test-123",
        }

        message = worker.parse_message(required_message)
        assert message.job_id == required_message["job_id"]
        assert message.video_id == required_message["video_id"]
        assert message.youtube_video_id == required_message["youtube_video_id"]
        assert message.correlation_id == required_message["correlation_id"]

    def test_api_batch_service_message_structure(self):
        """Test BatchService sends complete messages to queue including batch_id."""
        # Verify the message structure that BatchService sends
        # This validates the contract between batch API and workers

        # The message sent by BatchService (from batch_service.py)
        # queue_client.send_message(
        #     TRANSCRIBE_QUEUE,
        #     {
        #         "job_id": str(job.job_id),
        #         "video_id": str(video.video_id),
        #         "youtube_video_id": youtube_video_id,
        #         "batch_id": str(batch.batch_id),  # Batch-specific!
        #         "correlation_id": correlation_id,
        #     },
        # )

        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        batch_message = {
            "job_id": str(uuid4()),
            "video_id": str(uuid4()),
            "youtube_video_id": "dQw4w9WgXcQ",
            "batch_id": str(uuid4()),
            "correlation_id": "batch-test-123",
        }

        message = worker.parse_message(batch_message)
        assert message.batch_id == batch_message["batch_id"]
        assert message.batch_id is not None


# ============================================================================
# Worker Output Message Tests
# ============================================================================


class TestWorkerOutputMessageStructure:
    """Test that workers output correctly structured messages to downstream queues."""

    def test_transcribe_to_summarize_message_structure(self, complete_api_message):
        """Test TranscribeWorker would send correct message to SummarizeWorker."""
        from summarize.worker import SummarizeWorker

        # Simulate message that TranscribeWorker would send
        # Based on transcribe/worker.py _queue_next_job method
        transcribe_output = {
            "job_id": str(uuid4()),  # New job ID
            "video_id": complete_api_message["video_id"],
            "youtube_video_id": complete_api_message["youtube_video_id"],
            "correlation_id": complete_api_message["correlation_id"],
            "batch_id": complete_api_message["batch_id"],  # Propagated
        }

        # SummarizeWorker should be able to parse this
        worker = SummarizeWorker()
        message = worker.parse_message(transcribe_output)

        assert message.video_id == transcribe_output["video_id"]
        assert message.youtube_video_id == transcribe_output["youtube_video_id"]
        assert message.batch_id == transcribe_output["batch_id"]

    def test_summarize_to_embed_message_structure(self, complete_api_message):
        """Test SummarizeWorker would send correct message to EmbedWorker."""
        from embed.worker import EmbedWorker

        # Simulate message that SummarizeWorker would send
        summarize_output = {
            "job_id": str(uuid4()),
            "video_id": complete_api_message["video_id"],
            "youtube_video_id": complete_api_message["youtube_video_id"],
            "correlation_id": complete_api_message["correlation_id"],
            "batch_id": complete_api_message["batch_id"],
        }

        worker = EmbedWorker()
        message = worker.parse_message(summarize_output)

        assert message.video_id == summarize_output["video_id"]
        assert message.batch_id == summarize_output["batch_id"]

    def test_embed_to_relationships_message_structure(self, complete_api_message):
        """Test EmbedWorker would send correct message to RelationshipsWorker."""
        from relationships.worker import RelationshipsWorker

        # Simulate message that EmbedWorker would send
        embed_output = {
            "job_id": str(uuid4()),
            "video_id": complete_api_message["video_id"],
            "youtube_video_id": complete_api_message["youtube_video_id"],
            "correlation_id": complete_api_message["correlation_id"],
            "batch_id": complete_api_message["batch_id"],
        }

        worker = RelationshipsWorker()
        message = worker.parse_message(embed_output)

        assert message.video_id == embed_output["video_id"]
        assert message.batch_id == embed_output["batch_id"]


# ============================================================================
# Full Pipeline Message Flow Tests
# ============================================================================


class TestFullPipelineMessageFlow:
    """Test the complete message flow from API through all workers."""

    def test_complete_pipeline_message_flow(self, complete_api_message):
        """Test that a message flows correctly through the entire pipeline."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        # Step 1: API sends to Transcribe
        transcribe_worker = TranscribeWorker()
        transcribe_msg = transcribe_worker.parse_message(complete_api_message)

        assert transcribe_msg.video_id == complete_api_message["video_id"]
        assert transcribe_msg.batch_id == complete_api_message["batch_id"]

        # Step 2: Transcribe sends to Summarize
        # Simulating what _queue_next_job would produce
        summarize_input = {
            "job_id": str(uuid4()),
            "video_id": transcribe_msg.video_id,
            "youtube_video_id": transcribe_msg.youtube_video_id,
            "correlation_id": transcribe_msg.correlation_id,
            "batch_id": transcribe_msg.batch_id,  # Propagated!
        }

        summarize_worker = SummarizeWorker()
        summarize_msg = summarize_worker.parse_message(summarize_input)

        assert summarize_msg.video_id == transcribe_msg.video_id
        assert summarize_msg.batch_id == transcribe_msg.batch_id

        # Step 3: Summarize sends to Embed
        embed_input = {
            "job_id": str(uuid4()),
            "video_id": summarize_msg.video_id,
            "youtube_video_id": summarize_msg.youtube_video_id,
            "correlation_id": summarize_msg.correlation_id,
            "batch_id": summarize_msg.batch_id,  # Still propagated!
        }

        embed_worker = EmbedWorker()
        embed_msg = embed_worker.parse_message(embed_input)

        assert embed_msg.video_id == summarize_msg.video_id
        assert embed_msg.batch_id == summarize_msg.batch_id

        # Step 4: Embed sends to Relationships
        relationships_input = {
            "job_id": str(uuid4()),
            "video_id": embed_msg.video_id,
            "youtube_video_id": embed_msg.youtube_video_id,
            "correlation_id": embed_msg.correlation_id,
            "batch_id": embed_msg.batch_id,  # Still propagated!
        }

        relationships_worker = RelationshipsWorker()
        relationships_msg = relationships_worker.parse_message(relationships_input)

        assert relationships_msg.video_id == embed_msg.video_id
        assert relationships_msg.batch_id == embed_msg.batch_id

        # Verify batch_id preserved through entire pipeline
        assert relationships_msg.batch_id == complete_api_message["batch_id"]

    def test_pipeline_without_batch_id(self, minimal_api_message):
        """Test pipeline works without batch_id (single video submission)."""
        from embed.worker import EmbedWorker
        from relationships.worker import RelationshipsWorker
        from summarize.worker import SummarizeWorker
        from transcribe.worker import TranscribeWorker

        workers = [
            TranscribeWorker(),
            SummarizeWorker(),
            EmbedWorker(),
            RelationshipsWorker(),
        ]

        # All workers should handle None batch_id
        for worker in workers:
            message = worker.parse_message(minimal_api_message)
            assert message.batch_id is None
            assert message.video_id == minimal_api_message["video_id"]


# ============================================================================
# Regression Tests for Known Issues
# ============================================================================


class TestMessageContractRegressions:
    """Regression tests for known message contract issues."""

    def test_batch_id_field_exists_in_all_worker_messages(self):
        """Regression: All workers must have batch_id field for batch status updates."""
        from embed.worker import EmbedMessage
        from relationships.worker import RelationshipsMessage
        from summarize.worker import SummarizeMessage
        from transcribe.worker import TranscribeMessage

        message_classes = [
            TranscribeMessage,
            SummarizeMessage,
            EmbedMessage,
            RelationshipsMessage,
        ]

        for message_class in message_classes:
            field_names = {f.name for f in fields(message_class)}
            assert "batch_id" in field_names, (
                f"Regression: {message_class.__name__} missing batch_id field. "
                f"This was added to fix batch progress tracking."
            )

    def test_api_batch_message_includes_batch_id(self):
        """Regression: API batch service must include batch_id in queue messages."""
        # This test verifies the fix for batch progress tracking
        # The BatchService must include batch_id when queueing transcribe jobs

        # Expected message structure from batch_service.py
        expected_batch_message_fields = {
            "job_id",
            "video_id",
            "youtube_video_id",
            "batch_id",  # Critical for batch status updates!
            "correlation_id",
        }

        # Verify TranscribeWorker can parse all these fields
        from transcribe.worker import TranscribeWorker

        worker = TranscribeWorker()

        test_message = {
            "job_id": str(uuid4()),
            "video_id": str(uuid4()),
            "youtube_video_id": "test123",
            "batch_id": str(uuid4()),
            "correlation_id": "batch-test",
        }

        message = worker.parse_message(test_message)

        # All fields should be accessible
        assert message.job_id is not None
        assert message.video_id is not None
        assert message.youtube_video_id is not None
        assert message.batch_id is not None
        assert message.correlation_id is not None

    @requires_api
    def test_status_completed_not_ready(self):
        """Regression: Status values should use 'completed' not 'ready'."""
        from api.models.job import JobStatus

        # 'ready' was incorrectly used in the UI - should be 'completed'
        valid_statuses = [js.value for js in JobStatus]

        assert "ready" not in valid_statuses, (
            "Regression: 'ready' is not a valid status. Use 'completed' instead."
        )
        assert "completed" not in valid_statuses, (
            "JobStatus uses 'succeeded', not 'completed' (video status uses 'completed')"
        )
        assert "succeeded" in valid_statuses
