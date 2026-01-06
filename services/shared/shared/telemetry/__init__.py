"""Shared telemetry configuration for OpenTelemetry."""

from .config import (
    add_span_event,
    configure_telemetry,
    extract_trace_context,
    get_tracer,
    inject_trace_context,
    record_exception_on_span,
)

__all__ = [
    "add_span_event",
    "configure_telemetry",
    "extract_trace_context",
    "get_tracer",
    "inject_trace_context",
    "record_exception_on_span",
]
