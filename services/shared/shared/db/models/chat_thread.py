"""ChatThread SQLAlchemy model for storing copilot conversation threads."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class ChatThread(Base, TimestampMixin):
    """Stores chat thread state for copilot conversations.
    
    Each thread contains the full message history and any agent state,
    enabling server-side persistence of conversations.
    """

    __tablename__ = "ChatThreads"

    # Thread ID - matches the threadId from CopilotKit frontend
    thread_id: Mapped[str] = mapped_column(
        String(100),
        primary_key=True,
    )
    
    # Optional title for the thread (auto-generated from first message)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    
    # JSON-serialized array of messages
    # Each message has: id, role, content, createdAt, etc.
    messages_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    
    # JSON-serialized agent state (optional)
    state_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Agent name this thread is associated with
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False, default="yt-summarizer")
    
    # Message count for quick access
    message_count: Mapped[int] = mapped_column(default=0, nullable=False)
    
    # Last run ID that was successfully processed for this thread
    # Used to prevent re-running the agent on the same message when loading a thread
    last_run_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # JSON-serialized query scope (channels, videoIds, etc.)
    # Persisted so we can restore context when loading the thread
    scope_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # JSON-serialized AI knowledge settings (useVideoContext, useLLMKnowledge, useWebSearch)
    # Persisted so we can restore settings when loading the thread
    ai_settings_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_chat_threads_agent", "agent_name"),
        Index("ix_chat_threads_updated", "updated_at"),
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        import json
        return {
            "threadId": self.thread_id,
            "title": self.title,
            "messages": json.loads(self.messages_json) if self.messages_json else [],
            "state": json.loads(self.state_json) if self.state_json else None,
            "agentName": self.agent_name,
            "messageCount": self.message_count,
            "scope": json.loads(self.scope_json) if self.scope_json else None,
            "aiSettings": json.loads(self.ai_settings_json) if self.ai_settings_json else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }
