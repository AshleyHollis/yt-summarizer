"""Batch ingestion API routes."""

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.db.connection import get_session
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")


from ..middleware.correlation import get_correlation_id
from ..models.batch import (
    BatchDetailResponse,
    BatchListResponse,
    BatchResponse,
    BatchRetryResponse,
    CreateBatchRequest,
)
from ..services.batch_service import BatchService

router = APIRouter(prefix="/api/v1/batches", tags=["Batches"])


def get_batch_service(session: AsyncSession = Depends(get_session)) -> BatchService:
    """Dependency to get batch service."""
    return BatchService(session)


@router.post(
    "",
    response_model=BatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Batch",
    description="Create a batch for video ingestion from selected videos or entire channel",
)
async def create_batch(
    request: Request,
    body: CreateBatchRequest,
    service: BatchService = Depends(get_batch_service),
) -> BatchResponse:
    """Create a batch for video ingestion.

    Accepts a list of YouTube video IDs or ingestAll flag to
    ingest all videos from a channel. Creates video records,
    batch items, and queues transcription jobs.
    """
    correlation_id = get_correlation_id(request)

    try:
        result = await service.create_batch(body, correlation_id)
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


@router.get(
    "",
    response_model=BatchListResponse,
    summary="List Batches",
    description="Get paginated list of batches",
)
async def list_batches(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    service: BatchService = Depends(get_batch_service),
) -> BatchListResponse:
    """Get paginated list of batches.

    Returns batch summaries with status counts.
    """
    return await service.get_batches(page=page, page_size=page_size)


@router.get(
    "/{batch_id}",
    response_model=BatchDetailResponse,
    summary="Get Batch",
    description="Get batch details by ID",
)
async def get_batch(
    batch_id: UUID,
    service: BatchService = Depends(get_batch_service),
) -> BatchDetailResponse:
    """Get batch details including all items.

    Returns full batch information with status of each video.
    """
    result = await service.get_batch(batch_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch not found",
        )

    return result


@router.get(
    "/{batch_id}/stream",
    summary="Stream Batch Progress",
    description="Server-Sent Events stream for real-time batch progress updates",
)
async def stream_batch_progress(
    batch_id: UUID,
    service: BatchService = Depends(get_batch_service),
):
    """Stream batch progress via Server-Sent Events.

    Sends updates every 2 seconds until batch completes or client disconnects.
    """

    async def event_generator():
        """Generate SSE events with batch status updates."""
        try:
            while True:
                # Fetch current batch state
                batch = await service.get_batch(batch_id)

                if not batch:
                    # Send error and close stream
                    yield f"event: error\ndata: {json.dumps({'error': 'Batch not found'})}\n\n"
                    break

                # Send batch data
                batch_data = batch.model_dump(mode="json")
                yield f"data: {json.dumps(batch_data)}\n\n"

                # Check if batch is complete
                is_complete = (
                    batch.status == "completed"
                    or (
                        batch.succeeded_count + batch.failed_count == batch.total_count
                        and batch.pending_count == 0
                        and batch.running_count == 0
                    )
                )

                if is_complete:
                    # Send completion event and close stream
                    yield f"event: complete\ndata: {json.dumps(batch_data)}\n\n"
                    break

                # Wait before next update
                await asyncio.sleep(2)

        except asyncio.CancelledError:
            # Client disconnected
            pass
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.post(
    "/{batch_id}/retry",
    response_model=BatchRetryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Retry Failed Items",
    description="Retry all failed videos in a batch",
)
async def retry_batch_failures(
    request: Request,
    batch_id: UUID,
    service: BatchService = Depends(get_batch_service),
) -> BatchRetryResponse:
    """Retry all failed items in a batch.

    Resets failed items to pending and queues new jobs.
    """
    correlation_id = get_correlation_id(request)

    try:
        result = await service.retry_failed_items(batch_id, correlation_id)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        import traceback

        error_detail = f"{type(e).__name__}: {e!s}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )


@router.post(
    "/{batch_id}/items/{video_id}/retry",
    response_model=BatchRetryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Retry Single Item",
    description="Retry a single failed video in a batch",
)
async def retry_batch_item(
    request: Request,
    batch_id: UUID,
    video_id: UUID,
    service: BatchService = Depends(get_batch_service),
) -> BatchRetryResponse:
    """Retry a single failed item in a batch.

    Resets the item to pending and queues a new job.
    """
    correlation_id = get_correlation_id(request)

    try:
        result = await service.retry_single_item(batch_id, video_id, correlation_id)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        import traceback

        error_detail = f"{type(e).__name__}: {e!s}\n{traceback.format_exc()}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )
