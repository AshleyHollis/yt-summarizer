"""Base Pydantic response models."""

from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Generic type for paginated items
T = TypeVar("T")


class BaseResponse(BaseModel):
    """Base response model with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampMixin(BaseModel):
    """Mixin for created_at and updated_at fields."""

    created_at: datetime = Field(description="When the resource was created")
    updated_at: datetime = Field(description="When the resource was last updated")


class ErrorDetail(BaseModel):
    """Detailed error information."""

    field: str | None = Field(
        default=None, description="Field that caused the error (for validation errors)"
    )
    message: str = Field(description="Error message")
    type: str | None = Field(default=None, description="Error type code")


class ErrorResponse(BaseModel):
    """Standard error response model."""

    error: dict[str, Any] = Field(description="Error details")

    @classmethod
    def create(
        cls,
        code: int,
        message: str,
        correlation_id: str | None = None,
        details: list[ErrorDetail] | None = None,
    ) -> "ErrorResponse":
        """Create a standardized error response.

        Args:
            code: HTTP status code.
            message: Error message.
            correlation_id: Request correlation ID.
            details: Additional error details.

        Returns:
            ErrorResponse instance.
        """
        error = {
            "code": code,
            "message": message,
        }
        if correlation_id:
            error["correlation_id"] = correlation_id
        if details:
            error["details"] = [d.model_dump() for d in details]

        return cls(error=error)


class PaginationMeta(BaseModel):
    """Pagination metadata."""

    page: int = Field(ge=1, description="Current page number (1-indexed)")
    per_page: int = Field(ge=1, le=100, description="Items per page")
    total: int = Field(ge=0, description="Total number of items")
    total_pages: int = Field(ge=0, description="Total number of pages")
    has_next: bool = Field(description="Whether there is a next page")
    has_prev: bool = Field(description="Whether there is a previous page")

    @classmethod
    def create(
        cls,
        page: int,
        per_page: int,
        total: int,
    ) -> "PaginationMeta":
        """Create pagination metadata.

        Args:
            page: Current page number (1-indexed).
            per_page: Items per page.
            total: Total number of items.

        Returns:
            PaginationMeta instance.
        """
        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0

        return cls(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        )


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response model."""

    items: list[T] = Field(description="List of items")
    pagination: PaginationMeta = Field(description="Pagination metadata")

    @classmethod
    def create(
        cls,
        items: list[T],
        page: int,
        per_page: int,
        total: int,
    ) -> "PaginatedResponse[T]":
        """Create a paginated response.

        Args:
            items: List of items for this page.
            page: Current page number (1-indexed).
            per_page: Items per page.
            total: Total number of items.

        Returns:
            PaginatedResponse instance.
        """
        return cls(
            items=items,
            pagination=PaginationMeta.create(page, per_page, total),
        )


class UUIDResponse(BaseModel):
    """Response containing just a UUID (for create operations)."""

    id: UUID = Field(description="Resource ID")


class SuccessResponse(BaseModel):
    """Simple success response."""

    success: bool = Field(default=True, description="Operation was successful")
    message: str | None = Field(default=None, description="Optional success message")
