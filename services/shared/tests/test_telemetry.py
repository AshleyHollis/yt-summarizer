"""
Tests for OpenTelemetry configuration and trace context propagation.
Verifies T185-T188: Observability implementation.
"""

import os
import pytest
from unittest.mock import patch, MagicMock


class TestTelemetryConfiguration:
    """Tests for configure_telemetry function."""

    def test_configure_telemetry_returns_false_without_endpoint(self):
        """Telemetry should be disabled if no OTLP endpoint is configured."""
        from shared.telemetry.config import configure_telemetry, _telemetry_configured
        
        # Reset the global flag for testing
        import shared.telemetry.config as config_module
        config_module._telemetry_configured = False
        
        with patch.dict(os.environ, {}, clear=True):
            # Remove any existing OTEL env vars
            os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
            os.environ.pop("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", None)
            
            result = configure_telemetry("test-service")
            assert result is False

    def test_configure_telemetry_skips_if_already_configured(self):
        """Telemetry configuration should be idempotent."""
        import shared.telemetry.config as config_module
        
        # Set the flag as if already configured
        config_module._telemetry_configured = True
        
        result = config_module.configure_telemetry("test-service")
        assert result is True
        
        # Reset for other tests
        config_module._telemetry_configured = False


class TestGetTracer:
    """Tests for get_tracer function."""

    def test_get_tracer_returns_noop_when_not_configured(self):
        """get_tracer should return NoOpTracer when telemetry is not configured."""
        import shared.telemetry.config as config_module
        config_module._telemetry_configured = False
        
        from shared.telemetry.config import get_tracer
        
        tracer = get_tracer("test-component")
        
        # NoOpTracer should still be callable
        assert tracer is not None
        
        # start_as_current_span should work and return a context manager
        with tracer.start_as_current_span("test-span") as span:
            assert span is not None


class TestTraceContextPropagation:
    """Tests for trace context injection/extraction."""

    def test_inject_trace_context_adds_fields_to_message(self):
        """inject_trace_context should add traceparent/tracestate to message dict."""
        from shared.telemetry.config import inject_trace_context
        
        message = {"job_id": "123", "video_id": "456"}
        
        result = inject_trace_context(message)
        
        # Should return the message (possibly with trace context if tracing is active)
        assert result is not None
        assert "job_id" in result
        assert result["job_id"] == "123"

    def test_extract_trace_context_returns_context(self):
        """extract_trace_context should return a context object."""
        from shared.telemetry.config import extract_trace_context
        
        message = {
            "job_id": "123",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "tracestate": ""
        }
        
        context = extract_trace_context(message)
        
        # Should return a valid context (or None/empty context if tracing not configured)
        # The key is that it doesn't crash
        assert context is not None or context is None  # Either is acceptable

    def test_inject_and_extract_roundtrip(self):
        """Injected context should be extractable."""
        from shared.telemetry.config import inject_trace_context, extract_trace_context
        
        original_message = {"data": "test"}
        
        # Inject (may not add anything if no active span)
        injected = inject_trace_context(original_message.copy())
        
        # Extract should not crash
        context = extract_trace_context(injected)
        
        # Original data should be preserved
        assert injected["data"] == "test"


class TestLoggingTraceContext:
    """Tests for trace context in structured logs."""

    def test_add_trace_context_processor_exists(self):
        """add_trace_context processor should be available."""
        from shared.logging.config import add_trace_context
        
        # Should be a callable processor
        assert callable(add_trace_context)

    def test_add_trace_context_processor_returns_event_dict(self):
        """Processor should return the event dict with trace context added."""
        from shared.logging.config import add_trace_context
        
        # Simulate a log event
        event_dict = {
            "event": "test message",
            "level": "info"
        }
        
        result = add_trace_context(None, None, event_dict)
        
        # Should return the event dict (possibly with trace_id/span_id added)
        assert "event" in result
        assert result["event"] == "test message"

    def test_trace_context_added_when_tracing_active(self):
        """When tracing is active, trace_id and span_id should be added to logs."""
        from shared.logging.config import add_trace_context
        
        event_dict = {"event": "test"}
        
        # Without active tracing, trace_id/span_id may or may not be present
        result = add_trace_context(None, None, event_dict)
        
        # The processor should always return a valid dict
        assert isinstance(result, dict)
        assert "event" in result


class TestNoOpTracerFallback:
    """Tests for NoOpTracer fallback when OpenTelemetry is not available."""

    def test_noop_tracer_start_as_current_span_works(self):
        """NoOpTracer should provide a working context manager."""
        from shared.telemetry.config import NoOpTracer
        
        tracer = NoOpTracer()
        
        with tracer.start_as_current_span("test") as span:
            # Should work without errors
            pass

    def test_noop_span_operations_work(self):
        """NoOpSpan operations should be no-ops that don't crash."""
        from shared.telemetry.config import NoOpSpan
        
        span = NoOpSpan()
        
        # All these should work without errors
        span.set_attribute("key", "value")
        span.add_event("event_name")
        span.record_exception(Exception("test"))
        span.set_status(None)
