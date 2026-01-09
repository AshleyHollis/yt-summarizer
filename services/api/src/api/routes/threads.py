"""Thread management API routes for CopilotKit persistence.

Provides endpoints for managing chat threads:
- List threads
- Get thread details
- Delete threads
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.connection import get_session
    from shared.logging.config import get_logger
except ImportError:

    async def get_session():
        raise NotImplementedError("Database session not available")

    import logging

    def get_logger(name):
        return logging.getLogger(name)


from ..services.thread_service import ThreadService

router = APIRouter(prefix="/api/v1/threads", tags=["Threads"])
logger = get_logger(__name__)


# Response models
class ThreadSummary(BaseModel):
    """Summary of a chat thread (without full messages)."""

    thread_id: str
    title: str | None
    agent_name: str
    message_count: int
    created_at: str | None
    updated_at: str | None


class ThreadListResponse(BaseModel):
    """Response containing list of threads."""

    threads: list[ThreadSummary]
    total: int


class ThreadDetailResponse(BaseModel):
    """Full thread details including messages."""

    thread_id: str
    title: str | None
    messages: list[dict]
    state: dict | None
    agent_name: str
    message_count: int
    scope: dict | None = None
    aiSettings: dict | None = None
    created_at: str | None
    updated_at: str | None


class DeleteThreadResponse(BaseModel):
    """Response for thread deletion."""

    deleted: bool
    thread_id: str


class CreateThreadRequest(BaseModel):
    """Request to create a new thread."""

    thread_id: str
    title: str | None = None


class UpdateThreadMessagesRequest(BaseModel):
    """Request to update thread messages."""

    messages: list[dict]
    title: str | None = None
    scope: dict | None = None
    aiSettings: dict | None = None


class UpdateThreadMessagesResponse(BaseModel):
    """Response for thread update."""

    thread_id: str
    message_count: int
    updated_at: str | None


class UpdateThreadSettingsRequest(BaseModel):
    """Request to update thread scope and AI settings."""

    scope: dict | None = None
    aiSettings: dict | None = None


class UpdateThreadSettingsResponse(BaseModel):
    """Response for thread settings update."""

    thread_id: str
    scope: dict | None = None
    aiSettings: dict | None = None


class CreateThreadWithMessagesRequest(BaseModel):
    """Request to atomically create a thread with messages."""

    messages: list[dict]
    title: str | None = None
    scope: dict | None = None
    aiSettings: dict | None = None


class CreateThreadWithMessagesResponse(BaseModel):
    """Response for atomic thread creation with messages."""

    thread_id: str
    title: str | None
    message_count: int
    scope: dict | None = None
    aiSettings: dict | None = None
    created_at: str | None
    updated_at: str | None


class CreateThreadResponse(BaseModel):
    """Response for thread creation."""

    thread_id: str
    title: str | None
    message_count: int
    created_at: str | None
    updated_at: str | None


def get_thread_service(session: AsyncSession = Depends(get_session)) -> ThreadService:
    """Dependency to get thread service."""
    return ThreadService(session)


@router.post("", response_model=CreateThreadResponse, status_code=status.HTTP_201_CREATED)
async def create_thread(
    request: CreateThreadRequest,
    thread_service: ThreadService = Depends(get_thread_service),
) -> CreateThreadResponse:
    """Create a new empty chat thread.

    If the thread already exists, returns the existing thread (idempotent).

    Args:
        request: Thread creation request with thread_id and optional title.

    Returns:
        The created or existing thread.
    """
    logger.info(
        f"[THREAD CREATE EMPTY] Received request to create thread: {request.thread_id}, title: {request.title}"
    )
    try:
        thread = await thread_service.create_thread(
            thread_id=request.thread_id,
            title=request.title,
        )
        logger.info(f"[THREAD CREATE EMPTY] Created/returned thread: {thread['thread_id']}")

        return CreateThreadResponse(
            thread_id=thread["thread_id"],
            title=thread["title"],
            message_count=thread["message_count"],
            created_at=thread.get("created_at"),
            updated_at=thread.get("updated_at"),
        )
    except Exception as e:
        logger.error(f"Failed to create thread: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create thread",
        )


@router.post(
    "/messages",
    response_model=CreateThreadWithMessagesResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_thread_with_messages(
    request: CreateThreadWithMessagesRequest,
    thread_service: ThreadService = Depends(get_thread_service),
) -> CreateThreadWithMessagesResponse:
    """Atomically create a new thread with messages.

    This is the preferred endpoint for creating a new thread when the first
    message is sent. It generates a new thread_id and saves the messages
    in a single atomic operation, avoiding race conditions.

    Args:
        request: Messages to save and optional title.

    Returns:
        The created thread including the generated thread_id.
    """
    logger.info(
        f"[THREAD CREATE] Received request to create thread with {len(request.messages)} messages, title: {request.title}"
    )
    try:
        thread = await thread_service.create_thread_with_messages(
            messages=request.messages,
            title=request.title,
            scope=request.scope,
            ai_settings=request.aiSettings,
        )
        logger.info(f"[THREAD CREATE] Created thread: {thread['thread_id']}")

        return CreateThreadWithMessagesResponse(
            thread_id=thread["thread_id"],
            title=thread["title"],
            message_count=thread["message_count"],
            scope=thread.get("scope"),
            aiSettings=thread.get("aiSettings"),
            created_at=thread.get("created_at"),
            updated_at=thread.get("updated_at"),
        )
    except Exception as e:
        logger.error(f"Failed to create thread with messages: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create thread with messages",
        )


@router.get("", response_model=ThreadListResponse)
async def list_threads(
    agent_name: str | None = None,
    limit: int = 50,
    offset: int = 0,
    thread_service: ThreadService = Depends(get_thread_service),
) -> ThreadListResponse:
    """List chat threads.

    Args:
        agent_name: Optional filter by agent name.
        limit: Maximum number of threads to return.
        offset: Number of threads to skip.

    Returns:
        List of thread summaries.
    """
    try:
        threads = await thread_service.list_threads(
            agent_name=agent_name,
            limit=limit,
            offset=offset,
        )

        return ThreadListResponse(
            threads=[ThreadSummary(**t) for t in threads],
            total=len(threads),
        )
    except Exception as e:
        logger.error(f"Failed to list threads: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list threads",
        )


@router.get("/{thread_id}", response_model=ThreadDetailResponse)
async def get_thread(
    thread_id: str,
    thread_service: ThreadService = Depends(get_thread_service),
) -> ThreadDetailResponse:
    """Get a specific thread with full messages.

    Args:
        thread_id: The thread identifier.

    Returns:
        Full thread details including messages.
    """
    try:
        thread = await thread_service.get_thread(thread_id)

        if thread is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Thread {thread_id} not found",
            )

        return ThreadDetailResponse(**thread)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get thread {thread_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get thread",
        )


@router.patch("/{thread_id}/messages", response_model=UpdateThreadMessagesResponse)
async def update_thread_messages(
    thread_id: str,
    request: UpdateThreadMessagesRequest,
    thread_service: ThreadService = Depends(get_thread_service),
) -> UpdateThreadMessagesResponse:
    """Update thread messages (for frontend tool result persistence).

    This endpoint is called by the frontend to save the complete message history
    including tool results from frontend-executed tools.

    Args:
        thread_id: The thread identifier.
        request: The messages to save.

    Returns:
        Confirmation with updated message count.
    """
    try:
        result = await thread_service.save_thread(
            thread_id=thread_id,
            messages=request.messages,
            title=request.title,
            scope=request.scope,
            ai_settings=request.aiSettings,
        )

        return UpdateThreadMessagesResponse(
            thread_id=thread_id,
            message_count=result.get("message_count", len(request.messages)),
            updated_at=result.get("updated_at"),
        )
    except Exception as e:
        logger.error(f"Failed to update thread messages {thread_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update thread messages",
        )


@router.patch("/{thread_id}/settings", response_model=UpdateThreadSettingsResponse)
async def update_thread_settings(
    thread_id: str,
    request: UpdateThreadSettingsRequest,
    thread_service: ThreadService = Depends(get_thread_service),
) -> UpdateThreadSettingsResponse:
    """Update thread scope and AI knowledge settings.

    Called when the user changes settings mid-conversation.
    This allows persisting the new context so it's restored when reloading the thread.

    Args:
        thread_id: The thread identifier.
        request: The scope and/or AI settings to update.

    Returns:
        Confirmation with updated settings.
    """
    try:
        result = await thread_service.update_thread_settings(
            thread_id=thread_id,
            scope=request.scope,
            ai_settings=request.aiSettings,
        )

        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Thread {thread_id} not found",
            )

        return UpdateThreadSettingsResponse(
            thread_id=thread_id,
            scope=result.get("scope"),
            aiSettings=result.get("aiSettings"),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update thread settings {thread_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update thread settings",
        )


@router.delete("/{thread_id}", response_model=DeleteThreadResponse)
async def delete_thread(
    thread_id: str,
    thread_service: ThreadService = Depends(get_thread_service),
) -> DeleteThreadResponse:
    """Delete a chat thread.

    Args:
        thread_id: The thread identifier.

    Returns:
        Confirmation of deletion.
    """
    try:
        deleted = await thread_service.delete_thread(thread_id)

        return DeleteThreadResponse(
            deleted=deleted,
            thread_id=thread_id,
        )
    except Exception as e:
        logger.error(f"Failed to delete thread {thread_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete thread",
        )
