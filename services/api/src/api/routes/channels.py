"""Channel ingestion API routes."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")


from ..models.channel import (
    ChannelVideosResponse,
    FetchChannelRequest,
)
from ..services.channel_service import ChannelService
from ..dependencies.auth import AuthenticatedUser, require_auth

router = APIRouter(prefix="/api/v1/channels", tags=["Channels"])


def get_channel_service(
    session: AsyncSession = Depends(get_session),
) -> ChannelService:
    """Dependency to get channel service."""
    return ChannelService(session)


@router.post(
    "",
    response_model=ChannelVideosResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetch Channel Videos",
    description="Fetch videos from a YouTube channel for ingestion selection",
)
async def fetch_channel_videos(
    request: Request,
    body: FetchChannelRequest,
    user: AuthenticatedUser = Depends(require_auth),
    service: ChannelService = Depends(get_channel_service),
) -> ChannelVideosResponse:
    """Fetch videos from a YouTube channel.

    Uses yt-dlp to extract video list from the channel.
    Supports cursor-based pagination for loading more videos.
    Each video indicates if it's already ingested.
    """
    try:
        result = await service.fetch_channel_videos(body)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        import traceback

        error_detail = f"{type(e).__name__}: {e!s}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )
