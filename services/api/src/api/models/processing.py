"""Shared processing mode models."""

from enum import StrEnum


class ProcessingMode(StrEnum):
    """User-facing processing modes."""

    TRANSCRIPT_ONLY = "transcript_only"
    FULL_ANALYSIS = "full_analysis"


def normalize_processing_mode(value: str | ProcessingMode | None) -> ProcessingMode:
    """Normalize a processing mode value, defaulting to full analysis."""
    if value is None:
        return ProcessingMode.FULL_ANALYSIS
    return ProcessingMode(value)
