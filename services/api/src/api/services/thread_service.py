"""Thread service for persisting CopilotKit conversation threads.

This service handles saving and loading chat thread state to/from the database,
enabling server-side thread persistence for CopilotKit's AG-UI integration.
"""

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.db.models import ChatThread
    from shared.logging.config import get_logger
except ImportError as e:
    import logging
    logging.warning(f"Failed to import shared modules: {e}")
    ChatThread = None
    
    def get_logger(name):
        import logging
        return logging.getLogger(name)


logger = get_logger(__name__)


class ThreadService:
    """Service for managing chat thread persistence."""

    def __init__(self, session: AsyncSession):
        """Initialize the thread service.

        Args:
            session: Database session.
        """
        self.session = session

    async def get_thread(self, thread_id: str) -> dict[str, Any] | None:
        """Load a chat thread from the database.

        Args:
            thread_id: The unique thread identifier.

        Returns:
            Thread data dict with messages and state, or None if not found.
        """
        try:
            result = await self.session.execute(
                select(ChatThread).where(ChatThread.thread_id == thread_id)
            )
            thread = result.scalar_one_or_none()
            
            if thread is None:
                logger.debug(f"Thread {thread_id} not found")
                return None
            
            # Parse JSON fields
            messages = []
            state = None
            
            if thread.messages_json:
                try:
                    messages = json.loads(thread.messages_json)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse messages_json for thread {thread_id}")
                    messages = []
            
            if thread.state_json:
                try:
                    state = json.loads(thread.state_json)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse state_json for thread {thread_id}")
                    state = None
            
            logger.info(f"Loaded thread {thread_id} with {len(messages)} messages")
            
            # Parse scope and ai_settings
            scope = None
            ai_settings = None
            
            if thread.scope_json:
                try:
                    scope = json.loads(thread.scope_json)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse scope_json for thread {thread_id}")
                    scope = None
            
            if thread.ai_settings_json:
                try:
                    ai_settings = json.loads(thread.ai_settings_json)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse ai_settings_json for thread {thread_id}")
                    ai_settings = None
            
            return {
                "thread_id": thread.thread_id,
                "title": thread.title,
                "messages": messages,
                "state": state,
                "agent_name": thread.agent_name,
                "message_count": thread.message_count,
                "last_run_id": thread.last_run_id,
                "scope": scope,
                "aiSettings": ai_settings,
                "created_at": thread.created_at.isoformat() if thread.created_at else None,
                "updated_at": thread.updated_at.isoformat() if thread.updated_at else None,
            }
            
        except Exception as e:
            logger.error(f"Failed to load thread {thread_id}: {e}", exc_info=True)
            raise

    async def save_thread(
        self,
        thread_id: str,
        messages: list[dict[str, Any]],
        state: dict[str, Any] | None = None,
        title: str | None = None,
        agent_name: str = "yt-summarizer",
        last_run_id: str | None = None,
        scope: dict[str, Any] | None = None,
        ai_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Save or update a chat thread in the database.

        Args:
            thread_id: The unique thread identifier.
            messages: List of message dicts to save.
            state: Optional agent state dict to save.
            title: Optional thread title (auto-generated from first message if not provided).
            agent_name: Name of the agent this thread belongs to.
            last_run_id: The run_id of the last successful agent execution.
            scope: Optional query scope to persist (channels, videoIds, etc.).
            ai_settings: Optional AI knowledge settings to persist.

        Returns:
            The saved thread data.
        """
        try:
            # Auto-generate title from first user message if not provided
            if title is None and messages:
                for msg in messages:
                    if msg.get("role") == "user" and msg.get("content"):
                        content = msg["content"]
                        # Truncate to reasonable title length
                        title = content[:100] + "..." if len(content) > 100 else content
                        break
            
            # Serialize to JSON
            messages_json = json.dumps(messages)
            state_json = json.dumps(state) if state else None
            message_count = len(messages)
            
            # Check if thread exists
            result = await self.session.execute(
                select(ChatThread).where(ChatThread.thread_id == thread_id)
            )
            existing = result.scalar_one_or_none()
            
            now = datetime.now(UTC)
            
            if existing:
                # Update existing thread
                update_values = {
                    "messages_json": messages_json,
                    "state_json": state_json,
                    "title": title or existing.title,
                    "message_count": message_count,
                    "updated_at": now,
                }
                if last_run_id:
                    update_values["last_run_id"] = last_run_id
                if scope is not None:
                    update_values["scope_json"] = json.dumps(scope)
                if ai_settings is not None:
                    update_values["ai_settings_json"] = json.dumps(ai_settings)
                    update_values["last_run_id"] = last_run_id
                    
                await self.session.execute(
                    update(ChatThread)
                    .where(ChatThread.thread_id == thread_id)
                    .values(**update_values)
                )
                logger.info(f"[SAVE_THREAD] Updated existing thread {thread_id} with {message_count} messages")
            else:
                # Thread doesn't exist - DO NOT auto-create!
                # Threads should be created explicitly via create_thread or create_thread_with_messages.
                # CopilotKit may send requests with internally-generated thread IDs before
                # the frontend has created the thread, so just log and skip.
                logger.warning(f"[SAVE_THREAD] Thread {thread_id} does not exist, skipping save. "
                              f"Threads must be created via explicit API calls, not implicitly.")
            
            await self.session.commit()
            
            return {
                "thread_id": thread_id,
                "title": title,
                "messages": messages,
                "state": state,
                "agent_name": agent_name,
                "message_count": message_count,
            }
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to save thread {thread_id}: {e}", exc_info=True)
            raise

    async def list_threads(
        self,
        agent_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List chat threads, optionally filtered by agent.

        Args:
            agent_name: Optional agent name filter.
            limit: Maximum number of threads to return.
            offset: Number of threads to skip.

        Returns:
            List of thread summary dicts (without full messages).
        """
        try:
            query = select(ChatThread).order_by(ChatThread.updated_at.desc())
            
            if agent_name:
                query = query.where(ChatThread.agent_name == agent_name)
            
            query = query.limit(limit).offset(offset)
            
            result = await self.session.execute(query)
            threads = result.scalars().all()
            
            return [
                {
                    "thread_id": t.thread_id,
                    "title": t.title,
                    "agent_name": t.agent_name,
                    "message_count": t.message_count,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                    "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                }
                for t in threads
            ]
            
        except Exception as e:
            logger.error(f"Failed to list threads: {e}", exc_info=True)
            raise

    async def create_thread(
        self,
        thread_id: str,
        title: str | None = None,
        agent_name: str = "yt-summarizer",
        scope: dict[str, Any] | None = None,
        ai_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new empty chat thread.

        Args:
            thread_id: The unique thread identifier.
            title: Optional thread title.
            agent_name: Name of the agent this thread belongs to.
            scope: Optional query scope to persist.
            ai_settings: Optional AI knowledge settings to persist.

        Returns:
            The created thread data.
        """
        try:
            # Check if thread already exists
            result = await self.session.execute(
                select(ChatThread).where(ChatThread.thread_id == thread_id)
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                # Thread already exists, return it
                logger.debug(f"Thread {thread_id} already exists")
                return {
                    "thread_id": existing.thread_id,
                    "title": existing.title,
                    "messages": [],
                    "state": None,
                    "agent_name": existing.agent_name,
                    "message_count": existing.message_count,
                    "scope": json.loads(existing.scope_json) if existing.scope_json else None,
                    "aiSettings": json.loads(existing.ai_settings_json) if existing.ai_settings_json else None,
                    "created_at": existing.created_at.isoformat() if existing.created_at else None,
                    "updated_at": existing.updated_at.isoformat() if existing.updated_at else None,
                }
            
            # Create new empty thread
            thread = ChatThread(
                thread_id=thread_id,
                title=title or "New Chat",
                messages_json="[]",
                state_json=None,
                agent_name=agent_name,
                message_count=0,
                scope_json=json.dumps(scope) if scope else None,
                ai_settings_json=json.dumps(ai_settings) if ai_settings else None,
            )
            self.session.add(thread)
            await self.session.commit()
            
            logger.info(f"Created empty thread {thread_id}")
            
            return {
                "thread_id": thread_id,
                "title": title or "New Chat",
                "messages": [],
                "state": None,
                "agent_name": agent_name,
                "message_count": 0,
                "scope": scope,
                "aiSettings": ai_settings,
                "created_at": thread.created_at.isoformat() if thread.created_at else None,
                "updated_at": thread.updated_at.isoformat() if thread.updated_at else None,
            }
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to create thread {thread_id}: {e}", exc_info=True)
            raise

    async def delete_thread(self, thread_id: str) -> bool:
        """Delete a chat thread.

        Args:
            thread_id: The unique thread identifier.

        Returns:
            True if thread was deleted, False if not found.
        """
        try:
            result = await self.session.execute(
                delete(ChatThread).where(ChatThread.thread_id == thread_id)
            )
            await self.session.commit()
            
            deleted = result.rowcount > 0
            if deleted:
                logger.info(f"Deleted thread {thread_id}")
            else:
                logger.debug(f"Thread {thread_id} not found for deletion")
            
            return deleted
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to delete thread {thread_id}: {e}", exc_info=True)
            raise

    async def create_thread_with_messages(
        self,
        messages: list[dict[str, Any]],
        title: str | None = None,
        agent_name: str = "yt-summarizer",
        scope: dict[str, Any] | None = None,
        ai_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically create a new thread with messages.
        
        This is the preferred method for creating threads with initial messages,
        as it avoids race conditions by combining thread creation and message 
        saving into a single atomic operation.

        Args:
            messages: List of message dicts to save.
            title: Optional thread title (auto-generated from first message if not provided).
            agent_name: Name of the agent this thread belongs to.
            scope: Optional query scope to persist.
            ai_settings: Optional AI knowledge settings to persist.

        Returns:
            The created thread data including the generated thread_id.
        """
        import uuid
        
        try:
            thread_id = str(uuid.uuid4())
            
            # Auto-generate title from first user message if not provided
            if title is None and messages:
                for msg in messages:
                    if msg.get("role") == "user" and msg.get("content"):
                        content = msg["content"]
                        # Truncate to reasonable title length
                        title = content[:100] + "..." if len(content) > 100 else content
                        break
            
            # Serialize to JSON
            messages_json = json.dumps(messages)
            message_count = len(messages)
            now = datetime.now(UTC)
            
            # Create new thread with messages
            thread = ChatThread(
                thread_id=thread_id,
                title=title or "New Chat",
                messages_json=messages_json,
                state_json=None,
                agent_name=agent_name,
                message_count=message_count,
                scope_json=json.dumps(scope) if scope else None,
                ai_settings_json=json.dumps(ai_settings) if ai_settings else None,
            )
            self.session.add(thread)
            await self.session.commit()
            
            logger.info(f"Created thread {thread_id} with {message_count} messages atomically")
            
            return {
                "thread_id": thread_id,
                "title": title or "New Chat",
                "messages": messages,
                "state": None,
                "agent_name": agent_name,
                "message_count": message_count,
                "scope": scope,
                "aiSettings": ai_settings,
                "created_at": thread.created_at.isoformat() if thread.created_at else None,
                "updated_at": thread.updated_at.isoformat() if thread.updated_at else None,
            }
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to create thread with messages: {e}", exc_info=True)
            raise
    async def update_thread_settings(
        self,
        thread_id: str,
        scope: dict[str, Any] | None = None,
        ai_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Update scope and AI settings for an existing thread.
        
        Called when the user changes settings mid-conversation.

        Args:
            thread_id: The unique thread identifier.
            scope: Optional query scope to persist (replaces existing if provided).
            ai_settings: Optional AI knowledge settings to persist (replaces existing if provided).

        Returns:
            Updated thread data, or None if thread not found.
        """
        try:
            result = await self.session.execute(
                select(ChatThread).where(ChatThread.thread_id == thread_id)
            )
            existing = result.scalar_one_or_none()
            
            if not existing:
                logger.debug(f"Thread {thread_id} not found for settings update")
                return None
            
            update_values = {"updated_at": datetime.now(UTC)}
            
            if scope is not None:
                update_values["scope_json"] = json.dumps(scope)
            if ai_settings is not None:
                update_values["ai_settings_json"] = json.dumps(ai_settings)
            
            await self.session.execute(
                update(ChatThread)
                .where(ChatThread.thread_id == thread_id)
                .values(**update_values)
            )
            await self.session.commit()
            
            logger.info(f"Updated settings for thread {thread_id}")
            
            return {
                "thread_id": thread_id,
                "scope": scope if scope is not None else (json.loads(existing.scope_json) if existing.scope_json else None),
                "aiSettings": ai_settings if ai_settings is not None else (json.loads(existing.ai_settings_json) if existing.ai_settings_json else None),
            }
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update thread settings {thread_id}: {e}", exc_info=True)
            raise