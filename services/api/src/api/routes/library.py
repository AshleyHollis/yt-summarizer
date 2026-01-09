"""Library API routes for browsing and filtering videos."""

from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.connection import get_session
except ImportError:
    # Fallback for development
    async def get_session():
        raise NotImplementedError("Database session not available")


from ..models.channel import ChannelDetailResponse, ChannelListResponse
from ..models.facet import FacetListResponse
from ..models.library import (
    LibraryStatsResponse,
    ProcessingStatusFilter,
    SegmentListResponse,
    SortField,
    SortOrder,
    VideoDetailResponse,
    VideoFilterParams,
    VideoListResponse,
)
from ..services.library_service import LibraryService

router = APIRouter(prefix="/api/v1/library", tags=["Library"])


def get_library_service(session: AsyncSession = Depends(get_session)) -> LibraryService:
    """Dependency to get library service."""
    return LibraryService(session)


@router.get(
    "/videos",
    response_model=VideoListResponse,
    summary="List Videos",
    description="List videos with filtering, sorting, and pagination",
)
async def list_videos(
    channel_id: UUID | None = Query(default=None, description="Filter by channel ID"),
    from_date: date | None = Query(default=None, description="Filter by publish date (from)"),
    to_date: date | None = Query(default=None, description="Filter by publish date (to)"),
    facets: list[UUID] | None = Query(default=None, description="Filter by facet IDs"),
    status: ProcessingStatusFilter | None = Query(
        default=None, description="Filter by processing status"
    ),
    search: str | None = Query(
        default=None, max_length=200, description="Search in title/description"
    ),
    sort_by: SortField = Query(default=SortField.PUBLISH_DATE, description="Sort field"),
    sort_order: SortOrder = Query(default=SortOrder.DESC, description="Sort order"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=10, ge=1, le=50, description="Items per page"),
    service: LibraryService = Depends(get_library_service),
) -> VideoListResponse:
    """List videos with optional filtering.

    Supports filtering by channel, date range, facets, processing status,
    and text search. Results are paginated and can be sorted by various fields.
    """
    filters = VideoFilterParams(
        channel_id=channel_id,
        from_date=from_date,
        to_date=to_date,
        facets=facets,
        status=status,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )

    return await service.list_videos(filters)


@router.get(
    "/videos/{video_id}",
    response_model=VideoDetailResponse,
    summary="Get Video Detail",
    description="Get full video details including artifacts and facets",
)
async def get_video_detail(
    video_id: UUID,
    service: LibraryService = Depends(get_library_service),
) -> VideoDetailResponse:
    """Get detailed information about a video.

    Returns full video details including channel info, artifacts,
    segment count, relationship count, and facets.
    """
    result = await service.get_video_detail(video_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    return result


@router.get(
    "/videos/{video_id}/segments",
    response_model=SegmentListResponse,
    summary="List Video Segments",
    description="List transcript segments for a video with pagination",
)
async def list_segments(
    video_id: UUID,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    service: LibraryService = Depends(get_library_service),
) -> SegmentListResponse:
    """List transcript segments for a video.

    Returns paginated segments with timestamps. Each segment includes
    a YouTube URL with the timestamp for direct linking.
    """
    result = await service.list_segments(video_id, page, page_size)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    return result


@router.get(
    "/channels",
    response_model=ChannelListResponse,
    summary="List Channels",
    description="List channels with pagination and optional search",
)
async def list_channels(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=50, description="Items per page"),
    search: str | None = Query(default=None, max_length=100, description="Search by channel name"),
    service: LibraryService = Depends(get_library_service),
) -> ChannelListResponse:
    """List all channels with video counts.

    Returns paginated list of channels. Use search parameter
    to filter by channel name.
    """
    return await service.list_channels(page, page_size, search)


@router.get(
    "/channels/{channel_id}",
    response_model=ChannelDetailResponse,
    summary="Get Channel Detail",
    description="Get full channel details including video counts and top facets",
)
async def get_channel_detail(
    channel_id: UUID,
    service: LibraryService = Depends(get_library_service),
) -> ChannelDetailResponse:
    """Get detailed information about a channel.

    Returns full channel details including video counts,
    completion status, and top facets.
    """
    result = await service.get_channel_detail(channel_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Channel not found",
        )

    return result


@router.get(
    "/facets",
    response_model=FacetListResponse,
    summary="List Facets",
    description="List all facets with video counts for filtering UI",
)
async def list_facets(
    facet_type: str | None = Query(default=None, description="Filter by facet type"),
    min_count: int = Query(default=1, ge=0, description="Minimum video count to include"),
    service: LibraryService = Depends(get_library_service),
) -> FacetListResponse:
    """List facets with video counts.

    Returns all facets ordered by popularity (video count).
    Use facet_type to filter by type (topic, format, level, etc.).
    """
    return await service.list_facets(facet_type, min_count)


@router.get(
    "/stats",
    response_model=LibraryStatsResponse,
    summary="Get Library Stats",
    description="Get overall library statistics",
)
async def get_library_stats(
    service: LibraryService = Depends(get_library_service),
) -> LibraryStatsResponse:
    """Get overall library statistics.

    Returns counts of channels, videos, segments, relationships,
    and facets in the library.
    """
    return await service.get_library_stats()
