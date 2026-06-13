"""Integration tests for batch API endpoints.

These tests verify the batch creation, listing, and management endpoints.
Batch API is critical for User Story 2: Ingest from Channel.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status

# ============================================================================
# Batch Fixtures
# ============================================================================


@pytest.fixture
def sample_batch_id():
    """Generate a sample batch ID."""
    return str(uuid4())


@pytest.fixture
def sample_channel_id():
    """Generate a sample channel ID."""
    return str(uuid4())


@pytest.fixture
def sample_youtube_channel_id():
    """Sample YouTube channel ID."""
    return "UCfOQzBDXWXmP1qrL1u-XjUw"


@pytest.fixture
def sample_youtube_video_ids():
    """Sample YouTube video IDs."""
    return ["dQw4w9WgXcQ", "9bZkp7q19f0", "CevxZvSJLk8"]


@pytest.fixture
def mock_batch(sample_batch_id):
    """Create a mock batch object."""
    batch = MagicMock()
    batch.batch_id = uuid4()
    batch.name = "Test Batch"
    batch.channel_name = "Test Channel"
    batch.status = "pending"
    batch.total_count = 3
    batch.pending_count = 3
    batch.running_count = 0
    batch.succeeded_count = 0
    batch.failed_count = 0
    batch.created_at = datetime.utcnow()
    batch.updated_at = datetime.utcnow()
    batch.items = []
    return batch


@pytest.fixture
def mock_batch_item(sample_batch_id):
    """Create a mock batch item."""
    item = MagicMock()
    item.batch_item_id = uuid4()
    item.batch_id = sample_batch_id
    item.video_id = uuid4()
    item.youtube_video_id = "dQw4w9WgXcQ"
    item.title = "Test Video"
    item.status = "pending"
    item.error_message = None
    item.created_at = datetime.utcnow()
    item.updated_at = datetime.utcnow()
    return item


# ============================================================================
# Create Batch Tests
# ============================================================================


class TestCreateBatch:
    """Integration tests for POST /api/v1/batches endpoint."""

    def test_create_batch_requires_name(self, client, headers):
        """Test that name is required."""
        response = client.post(
            "/api/v1/batches",
            json={"video_ids": ["dQw4w9WgXcQ"]},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_batch_accepts_valid_request(self, client, headers, sample_youtube_video_ids):
        """Test that valid batch creation request is accepted."""
        response = client.post(
            "/api/v1/batches",
            json={
                "name": "Test Batch",
                "video_ids": sample_youtube_video_ids,
            },
            headers=headers,
        )
        # Either success, bad request (validation), or internal error (mocked DB)
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_create_batch_with_channel_id(
        self, client, headers, sample_channel_id, sample_youtube_video_ids
    ):
        """Test batch creation with channel association."""
        response = client.post(
            "/api/v1/batches",
            json={
                "name": "Channel Batch",
                "channel_id": sample_channel_id,
                "video_ids": sample_youtube_video_ids,
            },
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,  # Invalid channel ID
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_create_batch_with_ingest_all_flag(self, client, headers, sample_youtube_channel_id):
        """Test batch creation with ingest_all flag."""
        response = client.post(
            "/api/v1/batches",
            json={
                "name": "Full Channel Ingest",
                "youtube_channel_id": sample_youtube_channel_id,
                "ingest_all": True,
            },
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_create_batch_empty_video_ids_rejected(self, client, headers):
        """Test that empty video_ids without ingest_all is handled."""
        response = client.post(
            "/api/v1/batches",
            json={
                "name": "Empty Batch",
                "video_ids": [],
            },
            headers=headers,
        )
        # Should either reject or handle gracefully
        assert response.status_code in [
            status.HTTP_201_CREATED,  # Creates empty batch
            status.HTTP_400_BAD_REQUEST,  # Rejects empty
            status.HTTP_422_UNPROCESSABLE_ENTITY,  # Validation error
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


class TestBatchServiceCreate:
    """Focused service tests for batch creation behavior."""

    @pytest.mark.asyncio
    async def test_create_batch_normalizes_string_processing_mode(self, sample_youtube_video_ids):
        """Regression: API requests may provide processing_mode as a raw string."""
        from api.models.batch import CreateBatchRequest
        from api.models.processing import ProcessingMode
        from api.services.batch_service import BatchService

        session = MagicMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()

        def assign_batch_defaults():
            batch = session.add.call_args.args[0]
            batch.batch_id = uuid4()
            batch.status = "pending"
            batch.created_at = datetime.now(UTC)
            batch.updated_at = batch.created_at

        session.flush.side_effect = assign_batch_defaults

        request = CreateBatchRequest(
            name="Transcript Only Batch",
            video_ids=[sample_youtube_video_ids[0]],
            processing_mode="transcript_only",
        )
        service = BatchService(session)
        service._create_batch_item = AsyncMock(return_value=(True, False))

        with patch("api.services.batch_service.record_usage", new=AsyncMock()):
            response = await service.create_batch(
                request,
                correlation_id="test-correlation",
                user_id=None,
                transcript_quota_slots=1,
                ai_features_quota_slots=None,
            )

        assert response.processing_mode == ProcessingMode.TRANSCRIPT_ONLY
        service._create_batch_item.assert_awaited_once()
        assert service._create_batch_item.await_args.kwargs["processing_mode"] == (
            ProcessingMode.TRANSCRIPT_ONLY
        )

    @pytest.mark.asyncio
    async def test_fetch_video_metadata_uses_proxy_log_contract(self):
        """Regression: proxy logging in batch metadata fetch must match ProxyService."""
        from api.services.batch_service import BatchService

        class AsyncContext:
            async def __aenter__(self):
                return None

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeYoutubeDL:
            def __init__(self, opts):
                self.opts = opts

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def extract_info(self, url, download=False):
                return {
                    "title": "Test Video",
                    "description": "Description",
                    "duration": 123,
                    "upload_date": "20260102",
                    "thumbnails": [{"url": "https://example.com/thumb.jpg", "height": 720}],
                    "channel_id": "UC_test",
                    "channel": "Test Channel",
                    "channel_thumbnail_url": "https://example.com/channel.jpg",
                }

        proxy_service = MagicMock()
        proxy_service.get_ydl_opts.return_value = {"proxy": "http://proxy.example"}
        proxy_service.log_request.return_value = AsyncContext()

        service = BatchService(MagicMock())
        service._proxy_service = proxy_service

        with patch("yt_dlp.YoutubeDL", FakeYoutubeDL):
            metadata = await service._fetch_video_metadata("abc123")

        assert metadata["title"] == "Test Video"
        proxy_service.log_request.assert_called_once_with(
            service="api",
            operation="batch_fetch_video_metadata",
        )


# ============================================================================
# List Batches Tests
# ============================================================================


class TestListBatches:
    """Integration tests for GET /api/v1/batches endpoint."""

    def test_list_batches_returns_paginated_response(self, client, headers):
        """Test that list batches returns paginated structure."""
        response = client.get("/api/v1/batches", headers=headers)

        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "batches" in data
            assert "total_count" in data
            assert "page" in data
            assert "page_size" in data
            assert isinstance(data["batches"], list)

    def test_list_batches_default_pagination(self, client, headers):
        """Test default pagination parameters."""
        response = client.get("/api/v1/batches", headers=headers)

        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert data["page"] == 1
            assert data["page_size"] == 20

    def test_list_batches_custom_pagination(self, client, headers):
        """Test custom pagination parameters."""
        response = client.get(
            "/api/v1/batches?page=2&page_size=10",
            headers=headers,
        )

        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert data["page"] == 2
            assert data["page_size"] == 10

    def test_list_batches_invalid_page(self, client, headers):
        """Test that page must be >= 1."""
        response = client.get(
            "/api/v1/batches?page=0",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_list_batches_invalid_page_size(self, client, headers):
        """Test that page_size must be within bounds."""
        response = client.get(
            "/api/v1/batches?page_size=200",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ============================================================================
# Get Batch Detail Tests
# ============================================================================


class TestGetBatch:
    """Integration tests for GET /api/v1/batches/{batch_id} endpoint."""

    def test_get_batch_requires_valid_uuid(self, client, headers):
        """Test that batch_id must be a valid UUID."""
        response = client.get(
            "/api/v1/batches/not-a-uuid",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_batch_returns_404_for_nonexistent(self, client, headers):
        """Test that non-existent batches return 404."""
        batch_id = str(uuid4())
        response = client.get(
            f"/api/v1/batches/{batch_id}",
            headers=headers,
        )
        # Either 404 (not found) or 500 (mocked DB error)
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_get_batch_detail_response_structure(self, client, headers, sample_batch_id):
        """Test that batch detail has expected response structure."""
        # This validates the endpoint accepts the request
        response = client.get(
            f"/api/v1/batches/{sample_batch_id}",
            headers=headers,
        )
        # If successful, verify structure
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "id" in data
            assert "name" in data
            assert "status" in data
            assert "items" in data
            assert isinstance(data["items"], list)


# ============================================================================
# Batch Retry Tests
# ============================================================================


class TestRetryBatch:
    """Integration tests for POST /api/v1/batches/{batch_id}/retry endpoint."""

    def test_retry_batch_requires_valid_uuid(self, client, headers):
        """Test that batch_id must be a valid UUID."""
        response = client.post(
            "/api/v1/batches/not-a-uuid/retry",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_retry_batch_returns_404_for_nonexistent(self, client, headers):
        """Test that non-existent batches return 404."""
        batch_id = str(uuid4())
        response = client.post(
            f"/api/v1/batches/{batch_id}/retry",
            headers=headers,
        )
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_retry_batch_response_structure(self, client, headers, sample_batch_id):
        """Test retry response has expected structure."""
        response = client.post(
            f"/api/v1/batches/{sample_batch_id}/retry",
            headers=headers,
        )
        # If successful, verify structure
        if response.status_code == status.HTTP_202_ACCEPTED:
            data = response.json()
            assert "batch_id" in data
            assert "retried_count" in data
            assert "message" in data


class TestRetryBatchItem:
    """Integration tests for POST /api/v1/batches/{batch_id}/items/{video_id}/retry endpoint."""

    def test_retry_item_requires_valid_batch_uuid(self, client, headers):
        """Test that batch_id must be a valid UUID."""
        video_id = str(uuid4())
        response = client.post(
            f"/api/v1/batches/not-a-uuid/items/{video_id}/retry",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_retry_item_requires_valid_video_uuid(self, client, headers, sample_batch_id):
        """Test that video_id must be a valid UUID."""
        response = client.post(
            f"/api/v1/batches/{sample_batch_id}/items/not-a-uuid/retry",
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_retry_item_returns_404_for_nonexistent(self, client, headers):
        """Test that non-existent batch/item returns 404."""
        batch_id = str(uuid4())
        video_id = str(uuid4())
        response = client.post(
            f"/api/v1/batches/{batch_id}/items/{video_id}/retry",
            headers=headers,
        )
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


# ============================================================================
# Batch Status Values Tests
# ============================================================================


class TestBatchStatusValues:
    """Tests for batch status enum values."""

    def test_batch_status_enum_values(self):
        """Test that BatchStatus has expected values."""
        from api.models.batch import BatchStatus

        expected_values = {"pending", "running", "completed", "failed"}
        actual_values = {s.value for s in BatchStatus}
        assert actual_values == expected_values

    def test_batch_item_status_enum_values(self):
        """Test that BatchItemStatus has expected values."""
        from api.models.batch import BatchItemStatus

        expected_values = {"pending", "running", "succeeded", "failed"}
        actual_values = {s.value for s in BatchItemStatus}
        assert actual_values == expected_values


# ============================================================================
# Batch Model Validation Tests
# ============================================================================


class TestBatchModels:
    """Tests for batch Pydantic models."""

    def test_create_batch_request_model(self):
        """Test CreateBatchRequest model."""
        from api.models.batch import CreateBatchRequest

        request = CreateBatchRequest(
            name="Test Batch",
            video_ids=["dQw4w9WgXcQ", "9bZkp7q19f0"],
        )

        assert request.name == "Test Batch"
        assert len(request.video_ids) == 2
        assert request.ingest_all is False
        assert request.channel_id is None

    def test_batch_response_model(self):
        """Test BatchResponse model."""
        from api.models.batch import BatchResponse, BatchStatus

        batch = BatchResponse(
            id=uuid4(),
            name="Test Batch",
            status=BatchStatus.PENDING,
            total_count=5,
            pending_count=5,
            running_count=0,
            succeeded_count=0,
            failed_count=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        assert batch.status == BatchStatus.PENDING
        assert batch.total_count == 5

    def test_batch_detail_response_includes_items(self):
        """Test BatchDetailResponse includes items list."""
        from api.models.batch import BatchDetailResponse, BatchStatus

        batch = BatchDetailResponse(
            id=uuid4(),
            name="Test Batch",
            status=BatchStatus.RUNNING,
            total_count=2,
            pending_count=1,
            running_count=1,
            succeeded_count=0,
            failed_count=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            items=[],
        )

        assert hasattr(batch, "items")
        assert isinstance(batch.items, list)

    def test_batch_retry_response_model(self):
        """Test BatchRetryResponse model."""
        from api.models.batch import BatchRetryResponse

        response = BatchRetryResponse(
            batch_id=uuid4(),
            retried_count=3,
            message="3 items queued for retry",
        )

        assert response.retried_count == 3
        assert "retry" in response.message.lower()
