"""Tests for job_service batch status updates.

These tests verify that job status updates correctly propagate to
BatchItem and Batch counts, which is critical for batch progress tracking.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_batch_id():
    """Generate a sample batch ID."""
    return uuid4()


@pytest.fixture
def sample_video_id():
    """Generate a sample video ID."""
    return uuid4()


@pytest.fixture
def sample_job_id():
    """Generate a sample job ID."""
    return uuid4()


def create_mock_job(
    job_id,
    video_id,
    batch_id=None,
    job_type="transcribe",
    status="pending",
    stage="queued",
):
    """Create a mock Job object."""
    job = MagicMock()
    job.job_id = job_id
    job.video_id = video_id
    job.batch_id = batch_id
    job.job_type = job_type
    job.status = status
    job.stage = stage
    job.started_at = None
    job.completed_at = None
    job.error_message = None
    job.progress = 0
    return job


def create_mock_batch_item(
    batch_id,
    video_id,
    status="pending",
):
    """Create a mock BatchItem object."""
    item = MagicMock()
    item.batch_id = batch_id
    item.video_id = video_id
    item.status = status
    return item


def create_mock_batch(
    batch_id,
    pending_count=10,
    running_count=0,
    succeeded_count=0,
    failed_count=0,
):
    """Create a mock Batch object."""
    batch = MagicMock()
    batch.batch_id = batch_id
    batch.pending_count = pending_count
    batch.running_count = running_count
    batch.succeeded_count = succeeded_count
    batch.failed_count = failed_count
    batch.completed_at = None
    return batch


def create_mock_video(video_id, processing_status="pending"):
    """Create a mock Video object."""
    video = MagicMock()
    video.video_id = video_id
    video.processing_status = processing_status
    video.error_message = None
    return video


# =============================================================================
# Batch Status Update Logic Tests
# =============================================================================


class TestBatchItemStatusTransitions:
    """Tests for BatchItem status transition logic.
    
    These tests verify the core rules:
    - When first job starts running → batch item goes to "running"
    - When any job fails → batch item goes to "failed"
    - When final job (build_relationships) succeeds → batch item goes to "succeeded"
    - When intermediate job succeeds → batch item stays "running"
    """

    @pytest.mark.asyncio
    async def test_first_job_running_updates_batch_item_to_running(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """When first job transitions to running, batch item should become running."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="transcribe",
            status="pending",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "pending")
        batch = create_mock_batch(sample_batch_id, pending_count=10)
        video = create_mock_video(sample_video_id)

        mock_session = AsyncMock()
        
        # Setup mock query results
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        # Return different results for different queries
        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="running")

        # Verify job was updated
        assert job.status == "running"
        
        # Verify batch item was updated to running
        assert batch_item.status == "running"
        
        # Verify batch counts were updated
        assert batch.pending_count == 9  # decremented
        assert batch.running_count == 1  # incremented

    @pytest.mark.asyncio
    async def test_any_job_failure_updates_batch_item_to_failed(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """When any job fails, batch item should become failed."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="transcribe",
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        batch = create_mock_batch(sample_batch_id, pending_count=5, running_count=5)
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(
                str(sample_job_id),
                status="failed",
                error_message="Transcription failed",
            )

        # Verify job was updated
        assert job.status == "failed"
        assert job.error_message == "Transcription failed"
        
        # Verify batch item was updated to failed
        assert batch_item.status == "failed"
        
        # Verify video was updated
        assert video.processing_status == "failed"
        assert video.error_message == "Transcription failed"
        
        # Verify batch counts
        assert batch.running_count == 4  # decremented
        assert batch.failed_count == 1  # incremented

    @pytest.mark.asyncio
    async def test_final_job_success_updates_batch_item_to_succeeded(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """When build_relationships job succeeds, batch item should become succeeded."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="build_relationships",  # Final job type
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        batch = create_mock_batch(sample_batch_id, pending_count=0, running_count=1)
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="succeeded")

        # Verify job was updated
        assert job.status == "succeeded"
        
        # Verify batch item was updated to succeeded
        assert batch_item.status == "succeeded"
        
        # Verify video processing status was updated
        assert video.processing_status == "completed"
        
        # Verify batch counts
        assert batch.running_count == 0  # decremented
        assert batch.succeeded_count == 1  # incremented
        
        # Verify batch is marked complete (no pending or running)
        assert batch.completed_at is not None

    @pytest.mark.asyncio
    async def test_intermediate_job_success_does_not_change_batch_item(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """When transcribe/summarize/embed succeeds, batch item should stay running."""
        for job_type in ["transcribe", "summarize", "embed"]:
            job = create_mock_job(
                sample_job_id,
                sample_video_id,
                batch_id=sample_batch_id,
                job_type=job_type,
                status="running",
            )
            batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
            batch = create_mock_batch(sample_batch_id, pending_count=0, running_count=5)

            mock_session = AsyncMock()
            
            job_result = MagicMock()
            job_result.scalar_one_or_none.return_value = job

            mock_session.execute = AsyncMock(return_value=job_result)

            mock_db = MagicMock()
            mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

            with patch("shared.db.job_service.get_db", return_value=mock_db):
                from shared.db.job_service import update_job_status
                
                await update_job_status(str(sample_job_id), status="succeeded")

            # Verify job was updated
            assert job.status == "succeeded"
            
            # Verify batch item was NOT updated (still running)
            # The status update should not be called for intermediate jobs
            assert batch_item.status == "running"


class TestBatchCountUpdates:
    """Tests for batch count updates."""

    @pytest.mark.asyncio
    async def test_batch_completed_when_all_items_finished(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """Batch should be marked complete when no pending or running items remain."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="build_relationships",
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        # Last running item
        batch = create_mock_batch(
            sample_batch_id,
            pending_count=0,
            running_count=1,  # This is the last one
            succeeded_count=9,
        )
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="succeeded")

        # Verify batch is marked complete
        assert batch.completed_at is not None
        assert batch.pending_count == 0
        assert batch.running_count == 0
        assert batch.succeeded_count == 10

    @pytest.mark.asyncio
    async def test_batch_not_completed_when_items_still_pending(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """Batch should NOT be marked complete if pending items remain."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="build_relationships",
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        batch = create_mock_batch(
            sample_batch_id,
            pending_count=5,  # Still have pending
            running_count=1,
            succeeded_count=4,
        )
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="succeeded")

        # Verify batch is NOT marked complete (still has pending)
        assert batch.completed_at is None


class TestJobWithoutBatch:
    """Tests for jobs that are not part of a batch."""

    @pytest.mark.asyncio
    async def test_job_without_batch_updates_only_job(
        self, sample_video_id, sample_job_id
    ):
        """Jobs without batch_id should only update the job, not batch."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=None,  # No batch
            job_type="transcribe",
            status="pending",
        )

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job

        mock_session.execute = AsyncMock(return_value=job_result)

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="running")

        # Verify job was updated
        assert job.status == "running"
        
        # Verify only one execute call (for the job query, no batch queries)
        assert mock_session.execute.call_count == 1


class TestHelperFunctions:
    """Tests for helper functions like mark_job_running, mark_job_completed, mark_job_failed."""

    @pytest.mark.asyncio
    async def test_mark_job_running(self, sample_job_id, sample_video_id):
        """Test mark_job_running helper function."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=None,
            job_type="transcribe",
            status="pending",
        )

        mock_session = AsyncMock()
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        mock_session.execute = AsyncMock(return_value=job_result)

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import mark_job_running
            
            await mark_job_running(str(sample_job_id))

        assert job.status == "running"
        assert job.stage == "running"

    @pytest.mark.asyncio
    async def test_mark_job_completed(self, sample_job_id, sample_video_id):
        """Test mark_job_completed helper function."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=None,
            job_type="transcribe",
            status="running",
        )

        mock_session = AsyncMock()
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        mock_session.execute = AsyncMock(return_value=job_result)

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import mark_job_completed
            
            await mark_job_completed(str(sample_job_id))

        assert job.status == "succeeded"
        assert job.stage == "completed"
        assert job.progress == 100

    @pytest.mark.asyncio
    async def test_mark_job_failed(self, sample_job_id, sample_video_id):
        """Test mark_job_failed helper function."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=None,
            job_type="transcribe",
            status="running",
        )

        mock_session = AsyncMock()
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        mock_session.execute = AsyncMock(return_value=job_result)

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import mark_job_failed
            
            await mark_job_failed(str(sample_job_id), "Test error message")

        assert job.status == "failed"
        assert job.stage == "failed"
        assert job.error_message == "Test error message"


class TestVideoProcessingStatusSync:
    """Tests for video processing_status synchronization with batch item status."""

    @pytest.mark.asyncio
    async def test_video_status_updated_to_failed_on_job_failure(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """Video processing_status should be 'failed' when any job fails."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="summarize",
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        batch = create_mock_batch(sample_batch_id, pending_count=0, running_count=5)
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(
                str(sample_job_id),
                status="failed",
                error_message="Summarization failed",
            )

        # Verify video was updated
        assert video.processing_status == "failed"
        assert video.error_message == "Summarization failed"

    @pytest.mark.asyncio
    async def test_video_status_updated_to_completed_on_final_job_success(
        self, sample_batch_id, sample_video_id, sample_job_id
    ):
        """Video processing_status should be 'completed' when final job succeeds."""
        job = create_mock_job(
            sample_job_id,
            sample_video_id,
            batch_id=sample_batch_id,
            job_type="build_relationships",
            status="running",
        )
        batch_item = create_mock_batch_item(sample_batch_id, sample_video_id, "running")
        batch = create_mock_batch(sample_batch_id, pending_count=0, running_count=1)
        video = create_mock_video(sample_video_id, "processing")

        mock_session = AsyncMock()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = job
        
        batch_item_result = MagicMock()
        batch_item_result.scalar_one_or_none.return_value = batch_item
        
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = video
        
        batch_result = MagicMock()
        batch_result.scalar_one_or_none.return_value = batch

        mock_session.execute = AsyncMock(
            side_effect=[job_result, batch_item_result, video_result, batch_result]
        )

        mock_db = MagicMock()
        mock_db.session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db.session.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("shared.db.job_service.get_db", return_value=mock_db):
            from shared.db.job_service import update_job_status
            
            await update_job_status(str(sample_job_id), status="succeeded")

        # Verify video was updated to completed
        assert video.processing_status == "completed"
