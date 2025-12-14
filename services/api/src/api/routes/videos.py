"""Video API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.connection import get_session
    from shared.blob.client import get_blob_client, TRANSCRIPTS_CONTAINER, SUMMARIES_CONTAINER
except ImportError:
    # Fallback for development
    async def get_session():
        raise NotImplementedError("Database session not available")
    
    def get_blob_client():
        raise NotImplementedError("Blob client not available")
    
    TRANSCRIPTS_CONTAINER = "transcripts"
    SUMMARIES_CONTAINER = "summaries"


from ..middleware.correlation import get_correlation_id
from ..models.video import (
    ReprocessVideoRequest,
    SubmitVideoRequest,
    SubmitVideoResponse,
    VideoResponse,
)
from ..services.video_service import VideoService

router = APIRouter(prefix="/api/v1/videos", tags=["Videos"])


def get_video_service(session: AsyncSession = Depends(get_session)) -> VideoService:
    """Dependency to get video service."""
    return VideoService(session)


@router.post(
    "",
    response_model=SubmitVideoResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Video",
    description="Submit a YouTube video URL for processing",
)
async def submit_video(
    request: Request,
    body: SubmitVideoRequest,
    service: VideoService = Depends(get_video_service),
) -> SubmitVideoResponse:
    """Submit a video for processing.

    Accepts a YouTube URL, validates it, fetches metadata,
    and queues the video for transcription, summarization,
    embedding, and relationship extraction.
    """
    correlation_id = get_correlation_id(request)

    try:
        result = await service.submit_video(body.url, correlation_id)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )


@router.get(
    "/{video_id}",
    response_model=VideoResponse,
    summary="Get Video",
    description="Get video details by ID",
)
async def get_video(
    video_id: UUID,
    service: VideoService = Depends(get_video_service),
) -> VideoResponse:
    """Get a video by ID.

    Returns video details including processing status,
    channel information, and metadata.
    """
    result = await service.get_video(video_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )

    return result


@router.post(
    "/{video_id}/reprocess",
    response_model=SubmitVideoResponse,
    summary="Reprocess Video",
    description="Reprocess a video from specific stages",
)
async def reprocess_video(
    request: Request,
    video_id: UUID,
    body: ReprocessVideoRequest | None = None,
    service: VideoService = Depends(get_video_service),
) -> SubmitVideoResponse:
    """Reprocess a video.

    Allows reprocessing from specific stages (transcribe, summarize,
    embed, relationships) or all stages if not specified.
    """
    correlation_id = get_correlation_id(request)
    stages = body.stages if body else None

    try:
        result = await service.reprocess_video(video_id, stages, correlation_id)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get(
    "/{video_id}/transcript",
    response_class=PlainTextResponse,
    summary="Get Video Transcript",
    description="Get the transcript text for a video",
)
async def get_video_transcript(
    video_id: UUID,
    service: VideoService = Depends(get_video_service),
) -> PlainTextResponse:
    """Get transcript content for a video.
    
    Returns the transcript as plain text.
    """
    # First verify the video exists
    video = await service.get_video(video_id)
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )
    
    # Try to fetch transcript from blob storage
    try:
        blob_client = get_blob_client()
        blob_name = f"{video_id}/{video.youtube_video_id}_transcript.txt"
        content = blob_client.download_blob(TRANSCRIPTS_CONTAINER, blob_name)
        return PlainTextResponse(content.decode("utf-8"), media_type="text/plain")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcript not found: {str(e)}",
        )


@router.get(
    "/{video_id}/summary",
    response_class=PlainTextResponse,
    summary="Get Video Summary",
    description="Get the summary markdown for a video",
)
async def get_video_summary(
    video_id: UUID,
    service: VideoService = Depends(get_video_service),
) -> PlainTextResponse:
    """Get summary content for a video.
    
    Returns the summary as markdown text.
    """
    # First verify the video exists
    video = await service.get_video(video_id)
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )
    
    # Try to fetch summary from blob storage
    try:
        blob_client = get_blob_client()
        blob_name = f"{video_id}/{video.youtube_video_id}_summary.md"
        content = blob_client.download_blob(SUMMARIES_CONTAINER, blob_name)
        return PlainTextResponse(content.decode("utf-8"), media_type="text/markdown")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Summary not found: {str(e)}",
        )
