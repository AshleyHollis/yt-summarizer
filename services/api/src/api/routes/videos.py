"""Video API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.blob.client import (
        LIBRARY_CONTAINER,
        SUMMARIES_CONTAINER,
        TRANSCRIPTS_CONTAINER,
        extract_blob_name_from_uri,
        get_blob_client,
        get_summary_blob_path,
        get_transcript_blob_path,
    )
    from shared.db.connection import get_session
    from shared.db.models import Artifact
except ImportError:
    # Fallback for development
    async def get_session():
        raise NotImplementedError("Database session not available")

    def get_blob_client():
        raise NotImplementedError("Blob client not available")

    def get_transcript_blob_path(channel_name: str, youtube_video_id: str) -> str:
        raise NotImplementedError("Blob path helper not available")

    def get_summary_blob_path(channel_name: str, youtube_video_id: str) -> str:
        raise NotImplementedError("Blob path helper not available")

    def extract_blob_name_from_uri(blob_uri: str, container_name: str) -> str:
        raise NotImplementedError("Blob URI helper not available")

    Artifact = None
    LIBRARY_CONTAINER = "library"
    TRANSCRIPTS_CONTAINER = "transcripts"
    SUMMARIES_CONTAINER = "summaries"


from ..dependencies.auth import AuthenticatedUser, require_auth
from ..dependencies.quota import (
    AI_FEATURES_OPERATION,
    TRANSCRIPT_EXTRACT_OPERATION,
    check_operation_quota,
    check_video_quota,
    get_or_create_user,
    record_usage,
)
from ..middleware.correlation import get_correlation_id
from ..models.job import JobType
from ..models.processing import ProcessingMode
from ..models.video import (
    AddAiFeaturesResponse,
    ReprocessVideoRequest,
    SubmitVideoRequest,
    SubmitVideoResponse,
    VideoResponse,
)
from ..services.video_service import VideoAlreadyExistsError, VideoNotFoundError, VideoService

router = APIRouter(prefix="/api/v1/videos", tags=["Videos"])


def get_video_service(session: AsyncSession = Depends(get_session)) -> VideoService:
    """Dependency to get video service."""
    return VideoService(session)


def _extract_artifact_ref(blob_uri: str, default_container: str) -> tuple[str, str]:
    for container_name in [LIBRARY_CONTAINER, TRANSCRIPTS_CONTAINER, SUMMARIES_CONTAINER]:
        marker = f"/{container_name}/"
        if marker in blob_uri:
            return container_name, extract_blob_name_from_uri(blob_uri, container_name)
    return default_container, extract_blob_name_from_uri(blob_uri, default_container)


async def get_artifact_blob_ref(
    session: AsyncSession,
    video_id: UUID,
    artifact_type: str,
    default_container: str,
) -> tuple[str, str] | None:
    """Get the blob name recorded for a video artifact."""
    if Artifact is None:
        return None

    result = await session.execute(
        select(Artifact.blob_uri)
        .where(Artifact.video_id == video_id, Artifact.artifact_type == artifact_type)
        .limit(1)
    )
    blob_uri = result.scalar_one_or_none()
    if not blob_uri:
        return None

    return _extract_artifact_ref(blob_uri, default_container)


def _get_reprocess_start_stage(stages: list[str] | None) -> JobType:
    """Match VideoService's stage selection so quota checks cover the queued work."""
    if not stages:
        return JobType.TRANSCRIBE

    for stage in [
        JobType.TRANSCRIBE,
        JobType.SUMMARIZE,
        JobType.EMBED,
        JobType.BUILD_RELATIONSHIPS,
    ]:
        if stage.value in stages:
            return stage

    return JobType.TRANSCRIBE


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
    user: AuthenticatedUser = Depends(require_auth),
    service: VideoService = Depends(get_video_service),
    session: AsyncSession = Depends(get_session),
) -> SubmitVideoResponse:
    """Submit a video for processing.

    Accepts a YouTube URL, validates it, fetches metadata,
    and queues the video for transcription, summarization,
    embedding, and relationship extraction.
    Quota-aware: if daily limit reached, job is quota_queued.
    """
    correlation_id = get_correlation_id(request)

    # Check quota and determine dispatch status
    db_user = await get_or_create_user(session, user)
    quota_info = await check_video_quota(session, db_user)

    # Determine quota_status for this single video
    quota_remaining = quota_info["remaining"]
    quota_status = "released" if quota_remaining is None or quota_remaining > 0 else "quota_queued"

    ai_quota_status = "released"
    if body.processing_mode == ProcessingMode.FULL_ANALYSIS:
        ai_quota_info = await check_operation_quota(session, db_user, AI_FEATURES_OPERATION)
        ai_remaining = ai_quota_info["remaining"]
        ai_quota_status = (
            "released"
            if quota_status == "released" and (ai_remaining is None or ai_remaining > 0)
            else "quota_queued"
        )

    try:
        result = await service.submit_video(
            body.url,
            correlation_id,
            user_id=str(db_user.user_id),
            quota_status=quota_status,
            ai_quota_status=ai_quota_status,
            processing_mode=body.processing_mode,
        )

        # Record usage if dispatched
        if quota_status == "released":
            await record_usage(
                session,
                db_user.user_id,
                TRANSCRIPT_EXTRACT_OPERATION,
                str(result.video_id),
            )
        if body.processing_mode == ProcessingMode.FULL_ANALYSIS and ai_quota_status == "released":
            await record_usage(
                session,
                db_user.user_id,
                AI_FEATURES_OPERATION,
                str(result.video_id),
            )
        if quota_status == "released" or ai_quota_status == "released":
            await session.commit()

        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except VideoAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Video already exists with status '{e.status.value}': video_id={e.video_id}",
        )
    except VideoNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        import traceback

        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )


@router.post(
    "/{video_id}/ai-features",
    response_model=AddAiFeaturesResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Add AI Features",
    description="Queue summary, semantic search, and relationships for a transcript-ready video",
)
async def add_ai_features(
    request: Request,
    video_id: UUID,
    user: AuthenticatedUser = Depends(require_auth),
    service: VideoService = Depends(get_video_service),
    session: AsyncSession = Depends(get_session),
) -> AddAiFeaturesResponse:
    """Queue the AI feature package for a video that already has a transcript."""
    correlation_id = get_correlation_id(request)
    db_user = await get_or_create_user(session, user)
    ai_quota_info = await check_operation_quota(session, db_user, AI_FEATURES_OPERATION)
    remaining = ai_quota_info["remaining"]
    quota_status = "released" if remaining is None or remaining > 0 else "quota_queued"

    try:
        result = await service.add_ai_features(
            video_id,
            correlation_id,
            user_id=str(db_user.user_id),
            quota_status=quota_status,
        )
        if (
            quota_status == "released"
            and result.job_id is not None
            and result.message == "AI features queued"
        ):
            await record_usage(
                session,
                db_user.user_id,
                AI_FEATURES_OPERATION,
                str(video_id),
            )
            await session.commit()
        return result
    except ValueError as e:
        message = str(e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
            if message == "Video not found"
            else status.HTTP_400_BAD_REQUEST,
            detail=message,
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


@router.delete(
    "/{video_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Video",
    description="Delete a video and all associated data",
)
async def delete_video(
    video_id: UUID,
    user: AuthenticatedUser = Depends(require_auth),
    service: VideoService = Depends(get_video_service),
) -> None:
    """Delete a video by ID.

    Deletes the video, associated jobs, and segments.
    """
    deleted = await service.delete_video(video_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found",
        )


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
    user: AuthenticatedUser = Depends(require_auth),
    service: VideoService = Depends(get_video_service),
    session: AsyncSession = Depends(get_session),
) -> SubmitVideoResponse:
    """Reprocess a video.

    Allows reprocessing from specific stages (transcribe, summarize,
    embed, relationships) or all stages if not specified.
    """
    correlation_id = get_correlation_id(request)
    stages = body.stages if body else None
    start_stage = _get_reprocess_start_stage(stages)

    db_user = await get_or_create_user(session, user)
    transcript_quota_status = "released"
    ai_quota_status = "released"

    if start_stage == JobType.TRANSCRIBE:
        transcript_quota = await check_operation_quota(
            session,
            db_user,
            TRANSCRIPT_EXTRACT_OPERATION,
        )
        remaining = transcript_quota["remaining"]
        transcript_quota_status = (
            "released" if remaining is None or remaining > 0 else "quota_queued"
        )

    ai_quota = await check_operation_quota(session, db_user, AI_FEATURES_OPERATION)
    ai_remaining = ai_quota["remaining"]
    ai_quota_status = (
        "released"
        if transcript_quota_status == "released" and (ai_remaining is None or ai_remaining > 0)
        else "quota_queued"
    )

    try:
        result = await service.reprocess_video(
            video_id,
            stages,
            correlation_id,
            user_id=str(db_user.user_id),
            quota_status=transcript_quota_status,
            ai_quota_status=ai_quota_status,
        )
        if start_stage == JobType.TRANSCRIBE and transcript_quota_status == "released":
            await record_usage(
                session,
                db_user.user_id,
                TRANSCRIPT_EXTRACT_OPERATION,
                str(video_id),
            )
        if ai_quota_status == "released":
            await record_usage(
                session,
                db_user.user_id,
                AI_FEATURES_OPERATION,
                str(video_id),
            )
        if transcript_quota_status == "released" or ai_quota_status == "released":
            await session.commit()
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

    # Prefer the persisted artifact URI. It matches how completed videos are stored
    # and avoids probing stale path formats that can be slow when missing.
    channel_name = video.channel.name if video.channel else "unknown-channel"
    artifact_blob_ref = await get_artifact_blob_ref(
        service.session,
        video_id,
        "transcript",
        TRANSCRIPTS_CONTAINER,
    )
    fallback_blob_name = get_transcript_blob_path(channel_name, video.youtube_video_id)
    blob_refs = [
        (LIBRARY_CONTAINER, fallback_blob_name),
        artifact_blob_ref,
        (TRANSCRIPTS_CONTAINER, fallback_blob_name),
    ]

    blob_client = get_blob_client()
    last_error: Exception | None = None
    for index, blob_ref in enumerate(dict.fromkeys(ref for ref in blob_refs if ref)):
        container_name, blob_name = blob_ref
        try:
            if index > 0 and not blob_client.blob_exists(container_name, blob_name):
                continue
            content = blob_client.download_blob(container_name, blob_name)
            return PlainTextResponse(content.decode("utf-8"), media_type="text/plain")
        except Exception as e:
            last_error = e

    if last_error is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcript not found: {str(last_error)}",
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Transcript not found",
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

    # Prefer the persisted artifact URI. It matches how completed videos are stored
    # and avoids probing stale path formats that can be slow when missing.
    channel_name = video.channel.name if video.channel else "unknown-channel"
    artifact_blob_ref = await get_artifact_blob_ref(
        service.session,
        video_id,
        "summary",
        SUMMARIES_CONTAINER,
    )
    fallback_blob_name = get_summary_blob_path(channel_name, video.youtube_video_id)
    blob_refs = [
        (LIBRARY_CONTAINER, fallback_blob_name),
        artifact_blob_ref,
        (SUMMARIES_CONTAINER, fallback_blob_name),
    ]

    blob_client = get_blob_client()
    last_error: Exception | None = None
    for index, blob_ref in enumerate(dict.fromkeys(ref for ref in blob_refs if ref)):
        container_name, blob_name = blob_ref
        try:
            if index > 0 and not blob_client.blob_exists(container_name, blob_name):
                continue
            content = blob_client.download_blob(container_name, blob_name)
            return PlainTextResponse(content.decode("utf-8"), media_type="text/markdown")
        except Exception as e:
            last_error = e

    if last_error is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Summary not found: {str(last_error)}",
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Summary not found",
    )


@router.post(
    "/{video_id}/refresh-metadata",
    response_model=VideoResponse,
    summary="Refresh Video Metadata",
    description="Refresh video metadata from YouTube (title, channel, etc.)",
)
async def refresh_video_metadata(
    video_id: UUID,
    user: AuthenticatedUser = Depends(require_auth),
    service: VideoService = Depends(get_video_service),
) -> VideoResponse:
    """Refresh video metadata from YouTube.

    Fetches the latest metadata from YouTube using yt-dlp
    and updates the video and channel records.
    """
    try:
        result = await service.refresh_metadata(video_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Video not found",
            )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        import traceback

        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )
