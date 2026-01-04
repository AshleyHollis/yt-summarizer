"""Synthesis Pydantic models for learning paths and watch lists (US6).

These models support structured outputs that synthesize content from the library
into actionable learning experiences.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .base import BaseResponse


class SynthesisType(str, Enum):
    """Types of synthesis outputs."""
    
    LEARNING_PATH = "learning_path"
    WATCH_LIST = "watch_list"


class Priority(str, Enum):
    """Priority levels for watch list items."""
    
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LearningPathEvidence(BaseModel):
    """Evidence supporting an item's position in the learning path."""
    
    video_id: UUID = Field(alias="videoId", description="Source video ID")
    segment_id: UUID | None = Field(
        default=None,
        alias="segmentId",
        description="Relevant segment ID"
    )
    segment_text: str | None = Field(
        default=None,
        alias="segmentText",
        description="Relevant transcript text"
    )
    youtube_url: str | None = Field(
        default=None,
        alias="youTubeUrl",
        description="YouTube URL with timestamp"
    )
    
    model_config = {"populate_by_name": True}


class LearningPathItem(BaseModel):
    """A single step in a learning path."""
    
    order: int = Field(ge=1, description="Position in the learning path (1-based)")
    video_id: UUID = Field(alias="videoId", description="Video to watch")
    youtube_video_id: str = Field(alias="youTubeVideoId", description="YouTube video ID")
    title: str = Field(description="Video title")
    channel_name: str = Field(alias="channelName", description="Channel name")
    thumbnail_url: str | None = Field(default=None, alias="thumbnailUrl")
    duration: int | None = Field(default=None, description="Duration in seconds")
    rationale: str = Field(
        description="Why this video is at this position: 'Introduces core concepts needed for later steps'"
    )
    learning_objectives: list[str] = Field(
        default_factory=list,
        alias="learningObjectives",
        description="What you'll learn from this video"
    )
    prerequisites: list[int] = Field(
        default_factory=list,
        description="Order numbers of prerequisite items"
    )
    evidence: list[LearningPathEvidence] = Field(
        default_factory=list,
        description="Evidence supporting this item's placement"
    )
    
    model_config = {"populate_by_name": True}


class LearningPath(BaseModel):
    """A synthesized learning path from library content.
    
    Ordered sequence of videos that teach a topic progressively,
    with rationale for the ordering.
    """
    
    title: str = Field(description="Learning path title: 'Kettlebell Fundamentals for Beginners'")
    description: str = Field(description="What this learning path covers")
    estimated_duration: int = Field(
        alias="estimatedDuration",
        description="Total duration in seconds"
    )
    items: list[LearningPathItem] = Field(
        default_factory=list,
        description="Ordered list of videos in the path"
    )
    coverage_summary: str = Field(
        alias="coverageSummary",
        description="Summary of what topics are covered"
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Topics not covered - 'what's missing' messaging"
    )
    
    model_config = {"populate_by_name": True}


class WatchListItem(BaseModel):
    """A single item in a watch list."""
    
    video_id: UUID = Field(alias="videoId", description="Video ID")
    youtube_video_id: str = Field(alias="youTubeVideoId", description="YouTube video ID")
    title: str = Field(description="Video title")
    channel_name: str = Field(alias="channelName", description="Channel name")
    thumbnail_url: str | None = Field(default=None, alias="thumbnailUrl")
    duration: int | None = Field(default=None, description="Duration in seconds")
    priority: Priority = Field(
        default=Priority.MEDIUM,
        description="Watch priority"
    )
    reason: str = Field(
        description="Why this video is recommended: 'Highly relevant to your interest in...'"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Categorization tags"
    )
    
    model_config = {"populate_by_name": True}


class WatchList(BaseModel):
    """A curated watch list synthesized from library content.
    
    Prioritized collection of videos matching user interests,
    without necessarily implying sequential viewing order.
    """
    
    title: str = Field(description="Watch list title: 'Deep Dives on Nutrition'")
    description: str = Field(description="What this watch list focuses on")
    total_duration: int = Field(
        alias="totalDuration",
        description="Total duration in seconds"
    )
    items: list[WatchListItem] = Field(
        default_factory=list,
        description="Prioritized list of videos"
    )
    criteria: str = Field(
        description="Criteria used to select these videos"
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Topics not covered - 'what's missing' messaging"
    )
    
    model_config = {"populate_by_name": True}


class SynthesizeRequest(BaseModel):
    """Request to synthesize structured output from library content."""
    
    synthesis_type: SynthesisType = Field(
        alias="synthesisType",
        description="Type of synthesis to perform"
    )
    query: str = Field(
        description="Natural language request: 'Create a learning path for kettlebell training'"
    )
    scope: "QueryScope | None" = Field(
        default=None,
        description="Optional scope filters"
    )
    max_items: int = Field(
        default=10,
        ge=1,
        le=50,
        alias="maxItems",
        description="Maximum number of items to include"
    )
    correlation_id: str | None = Field(
        default=None,
        alias="correlationId",
        description="Correlation ID for tracing"
    )
    
    model_config = {"populate_by_name": True}


class SynthesizeResponse(BaseResponse):
    """Response from a synthesis request."""
    
    synthesis_type: SynthesisType = Field(alias="synthesisType")
    learning_path: LearningPath | None = Field(
        default=None,
        alias="learningPath",
        description="Learning path if synthesisType is 'learning_path'"
    )
    watch_list: WatchList | None = Field(
        default=None,
        alias="watchList",
        description="Watch list if synthesisType is 'watch_list'"
    )
    insufficient_content: bool = Field(
        default=False,
        alias="insufficientContent",
        description="True if not enough content to synthesize meaningful output"
    )
    insufficient_message: str | None = Field(
        default=None,
        alias="insufficientMessage",
        description="Explanation of what content is missing"
    )
    
    model_config = {"populate_by_name": True}


# Import QueryScope for type hint - must be at bottom to avoid circular import
from .copilot import QueryScope

# Update forward reference
SynthesizeRequest.model_rebuild()
