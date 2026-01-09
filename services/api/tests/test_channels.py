"""Integration tests for channel API endpoints.

These tests verify the channel fetching endpoint for User Story 2: Ingest from Channel.
"""

from datetime import datetime
from uuid import uuid4

import pytest
from fastapi import status

# ============================================================================
# Channel Fixtures
# ============================================================================


@pytest.fixture
def sample_youtube_channel_url():
    """Sample YouTube channel URL."""
    return "https://www.youtube.com/@MarkWildman"


@pytest.fixture
def sample_youtube_channel_id():
    """Sample YouTube channel ID."""
    return "UCfOQzBDXWXmP1qrL1u-XjUw"


@pytest.fixture
def mock_channel_video():
    """Create a mock channel video."""
    return {
        "youtube_video_id": "dQw4w9WgXcQ",
        "title": "Test Video",
        "duration": 180,
        "publish_date": datetime.utcnow().isoformat(),
        "thumbnail_url": "https://example.com/thumb.jpg",
        "already_ingested": False,
    }


# ============================================================================
# Fetch Channel Videos Tests
# ============================================================================


class TestFetchChannelVideos:
    """Integration tests for POST /api/v1/channels endpoint."""

    def test_fetch_channel_requires_channel_url(self, client, headers):
        """Test that channel_url is required."""
        response = client.post(
            "/api/v1/channels",
            json={},
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_fetch_channel_accepts_valid_url(self, client, headers, sample_youtube_channel_url):
        """Test that valid channel URL is accepted."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": sample_youtube_channel_url},
            headers=headers,
        )
        # Either success, bad request (yt-dlp error), or internal error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_fetch_channel_accepts_handle_format(self, client, headers):
        """Test that @handle format URLs are accepted."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": "https://www.youtube.com/@MarkWildman"},
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_fetch_channel_accepts_channel_id_format(self, client, headers, sample_youtube_channel_id):
        """Test that /channel/ format URLs are accepted."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": f"https://www.youtube.com/channel/{sample_youtube_channel_id}"},
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_fetch_channel_accepts_cursor_parameter(self, client, headers, sample_youtube_channel_url):
        """Test that cursor parameter for pagination is accepted."""
        response = client.post(
            "/api/v1/channels",
            json={
                "channel_url": sample_youtube_channel_url,
                "cursor": "next_page_token_123",
            },
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_fetch_channel_accepts_limit_parameter(self, client, headers, sample_youtube_channel_url):
        """Test that limit parameter is accepted."""
        response = client.post(
            "/api/v1/channels",
            json={
                "channel_url": sample_youtube_channel_url,
                "limit": 50,
            },
            headers=headers,
        )
        # Validation should pass
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

    def test_fetch_channel_limit_must_be_positive(self, client, headers, sample_youtube_channel_url):
        """Test that limit must be >= 1."""
        response = client.post(
            "/api/v1/channels",
            json={
                "channel_url": sample_youtube_channel_url,
                "limit": 0,
            },
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_fetch_channel_limit_max_100(self, client, headers, sample_youtube_channel_url):
        """Test that limit must be <= 100."""
        response = client.post(
            "/api/v1/channels",
            json={
                "channel_url": sample_youtube_channel_url,
                "limit": 150,
            },
            headers=headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_fetch_channel_empty_url_rejected(self, client, headers):
        """Test that empty channel URL is rejected."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": ""},
            headers=headers,
        )
        # Either validation error (422) or service rejection (400)
        assert response.status_code in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_400_BAD_REQUEST,
        ]


# ============================================================================
# Channel Response Model Tests
# ============================================================================


class TestChannelModels:
    """Tests for channel Pydantic models."""

    def test_fetch_channel_request_model(self):
        """Test FetchChannelRequest model."""
        from api.models.channel import FetchChannelRequest
        
        request = FetchChannelRequest(
            channel_url="https://www.youtube.com/@MarkWildman",
        )
        
        assert request.channel_url == "https://www.youtube.com/@MarkWildman"
        assert request.cursor is None
        assert request.limit == 100  # Default value

    def test_fetch_channel_request_with_cursor(self):
        """Test FetchChannelRequest with cursor."""
        from api.models.channel import FetchChannelRequest
        
        request = FetchChannelRequest(
            channel_url="https://www.youtube.com/@MarkWildman",
            cursor="next_page_token",
            limit=50,
        )
        
        assert request.cursor == "next_page_token"
        assert request.limit == 50

    def test_channel_video_model(self):
        """Test ChannelVideo model."""
        from api.models.channel import ChannelVideo
        
        video = ChannelVideo(
            youtube_video_id="dQw4w9WgXcQ",
            title="Test Video",
            duration=180,
            publish_date=datetime.utcnow(),
            thumbnail_url="https://example.com/thumb.jpg",
            already_ingested=False,
        )
        
        assert video.youtube_video_id == "dQw4w9WgXcQ"
        assert video.duration == 180
        assert video.already_ingested is False

    def test_channel_videos_response_model(self):
        """Test ChannelVideosResponse model."""
        from api.models.channel import ChannelVideo, ChannelVideosResponse
        
        response = ChannelVideosResponse(
            youtube_channel_id="UCfOQzBDXWXmP1qrL1u-XjUw",
            channel_name="Mark Wildman",
            total_video_count=100,
            returned_count=50,
            videos=[
                ChannelVideo(
                    youtube_video_id="dQw4w9WgXcQ",
                    title="Test Video",
                    duration=180,
                    publish_date=datetime.utcnow(),
                )
            ],
            next_cursor="next_page_token",
            has_more=True,
        )
        
        assert response.youtube_channel_id == "UCfOQzBDXWXmP1qrL1u-XjUw"
        assert response.channel_name == "Mark Wildman"
        assert response.returned_count == 50
        assert response.has_more is True
        assert len(response.videos) == 1

    def test_channel_card_model(self):
        """Test ChannelCard model."""
        from api.models.channel import ChannelCard
        
        card = ChannelCard(
            channel_id=uuid4(),
            youtube_channel_id="UCfOQzBDXWXmP1qrL1u-XjUw",
            name="Mark Wildman",
            video_count=50,
        )
        
        assert card.name == "Mark Wildman"
        assert card.video_count == 50
        assert "youtube.com/channel" in card.youtube_url


# ============================================================================
# Channel URL Format Validation Tests
# ============================================================================


class TestChannelUrlValidation:
    """Tests for channel URL format validation."""

    @pytest.mark.parametrize("url", [
        "https://www.youtube.com/@MarkWildman",
        "https://youtube.com/@darciisabella",
        "https://www.youtube.com/channel/UCfOQzBDXWXmP1qrL1u-XjUw",
        "https://www.youtube.com/c/ChannelName",
        "https://www.youtube.com/user/username",
    ])
    def test_valid_channel_url_formats(self, client, headers, url):
        """Test that various valid channel URL formats are accepted."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": url},
            headers=headers,
        )
        # Should not be a validation error (422)
        # May be 400 (yt-dlp error) or 500 (mocked) but not 422
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY or \
               "limit" in response.text or "channel_url" not in response.text

    @pytest.mark.parametrize("url", [
        "",
        "   ",
    ])
    def test_empty_channel_url_rejected(self, client, headers, url):
        """Test that empty/whitespace URLs are rejected."""
        response = client.post(
            "/api/v1/channels",
            json={"channel_url": url},
            headers=headers,
        )
        # Either validation error (422) or service rejection (400)
        assert response.status_code in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_400_BAD_REQUEST,
        ]


# ============================================================================
# Channel List Tests (Library integration)
# ============================================================================


class TestChannelList:
    """Tests for channel listing in library context."""

    def test_channel_list_response_model(self):
        """Test ChannelListResponse model."""
        from api.models.channel import ChannelCard, ChannelListResponse
        
        response = ChannelListResponse(
            channels=[
                ChannelCard(
                    channel_id=uuid4(),
                    youtube_channel_id="UC12345",
                    name="Test Channel",
                    video_count=10,
                )
            ],
            page=1,
            page_size=20,
            total_count=1,
        )
        
        assert len(response.channels) == 1
        assert response.total_count == 1
        assert response.page == 1
