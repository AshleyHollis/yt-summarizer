# YT Summarizer Shared

Common code shared between API and workers.

## Modules

- **db/**: SQLAlchemy models and database connection
- **queue/**: Azure Storage Queue client wrapper
- **blob/**: Azure Blob Storage client wrapper  
- **logging/**: Structured logging configuration
- **telemetry/**: OpenTelemetry configuration and helpers
- **worker/**: Base worker class for queue processing
- **alembic/**: Database migrations

## Telemetry Module

The `telemetry` module provides OpenTelemetry integration for distributed tracing:

### Configuration

```python
from shared.telemetry import configure_telemetry, get_tracer

# Configure telemetry (call once at startup)
configure_telemetry(service_name="my-service")

# Get a tracer for your component
tracer = get_tracer("my_component")
```

### Trace Context Propagation

```python
from shared.telemetry.config import inject_trace_context, extract_trace_context

# Inject trace context into a message (producer side)
message = inject_trace_context({"video_id": "123"})
# Result: {"video_id": "123", "traceparent": "00-...", "tracestate": "..."}

# Extract trace context from a message (consumer side)
context = extract_trace_context(message)
with tracer.start_as_current_span("process", context=context):
    # Processing continues the same trace
    pass
```

### Span Links and Events

```python
from shared.telemetry.config import (
    create_span_link_from_message,
    add_span_event,
    record_exception_on_span,
)

# Create a span link to show producer-consumer relationship
span_link = create_span_link_from_message(message)
with tracer.start_as_current_span("process", links=[span_link] if span_link else []) as span:
    # Add events to mark key milestones
    add_span_event(span, "message_received", {"queue": "my-queue"})

    try:
        result = process(message)
        add_span_event(span, "processing_completed", {"status": "success"})
    except Exception as e:
        # Record exception with proper status
        record_exception_on_span(span, e, {"phase": "processing"})
        raise
```

### Span Events in Workers

The base worker automatically adds these span events:

| Event | Description |
|-------|-------------|
| `message_received` | Message dequeued from queue |
| `message_parsed` | Message successfully parsed |
| `processing_started` | Handler execution begins |
| `processing_completed` | Handler finished (includes status/duration) |
| `message_acknowledged` | Message deleted on success |
| `message_requeued` | Message requeued for retry |
| `message_dead_lettered` | Message exceeded max retries |
| `rate_limit_detected` | Rate limiting triggered |

## Installation

```bash
pip install -e ".[dev]"
```
