"""Facet Pydantic models for API responses."""

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from .base import BaseResponse


class FacetType(StrEnum):
    """Types of facets/tags."""

    TOPIC = "topic"
    FORMAT = "format"
    LEVEL = "level"
    LANGUAGE = "language"
    TOOL = "tool"
    CONCEPT = "concept"


class FacetCount(BaseResponse):
    """Facet with video count for filtering UI."""

    facet_id: UUID = Field(description="Facet ID")
    name: str = Field(description="Facet name")
    type: str = Field(description="Facet type")
    video_count: int = Field(description="Number of videos with this facet")


class FacetListResponse(BaseResponse):
    """List of facets with counts."""

    facets: list[FacetCount] = Field(description="List of facets with counts")
