"""Correlation ID middleware for request tracing.

This middleware ensures correlation IDs propagate through:
1. HTTP request/response headers (X-Correlation-ID)
2. Structured logging context
3. OpenTelemetry trace spans (as span attribute)
4. OpenTelemetry baggage (for cross-service propagation)
"""

import uuid
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Header name for correlation ID (following common conventions)
CORRELATION_ID_HEADER = "X-Correlation-ID"
REQUEST_ID_HEADER = "X-Request-ID"


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return str(uuid.uuid4())


def _set_trace_correlation(correlation_id: str) -> None:
    """Add correlation ID to the current trace span and baggage.
    
    This ensures the correlation ID propagates through:
    - The current span as an attribute (for filtering in dashboards)
    - OpenTelemetry baggage (for cross-service propagation)
    """
    try:
        from opentelemetry import baggage, trace
        from opentelemetry.context import attach, get_current
        
        # Add to current span as attribute
        span = trace.get_current_span()
        if span and span.is_recording():
            span.set_attribute("correlation_id", correlation_id)
            span.set_attribute("app.correlation_id", correlation_id)
        
        # Add to baggage for cross-service propagation
        ctx = baggage.set_baggage("correlation_id", correlation_id, get_current())
        attach(ctx)
        
    except ImportError:
        pass  # OpenTelemetry not available
    except Exception:
        pass  # Ignore telemetry errors


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware to handle correlation IDs for request tracing.
    
    This middleware:
    1. Extracts correlation ID from incoming request headers
    2. Generates a new one if not present
    3. Adds it to the response headers
    4. Makes it available throughout the request lifecycle
    5. Adds it to OpenTelemetry span and baggage for distributed tracing
    """
    
    def __init__(
        self,
        app: ASGIApp,
        header_name: str = CORRELATION_ID_HEADER,
        generator: Callable[[], str] = generate_correlation_id,
    ):
        """Initialize the middleware.
        
        Args:
            app: The ASGI application.
            header_name: The header name to use for correlation ID.
            generator: Function to generate new correlation IDs.
        """
        super().__init__(app)
        self.header_name = header_name
        self.generator = generator
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Response],
    ) -> Response:
        """Process the request, managing correlation ID.
        
        Args:
            request: The incoming request.
            call_next: The next middleware/handler.
        
        Returns:
            The response with correlation ID header.
        """
        # Get correlation ID from request header or generate new one
        correlation_id = request.headers.get(self.header_name)
        if not correlation_id:
            correlation_id = self.generator()
        
        # Store in request state for access by handlers
        request.state.correlation_id = correlation_id
        
        # Import here to avoid circular imports
        from shared.logging.config import bind_context, set_correlation_id, unbind_context
        
        # Set correlation ID for logging
        set_correlation_id(correlation_id)
        bind_context(correlation_id=correlation_id)
        
        # Add to OpenTelemetry trace span and baggage
        _set_trace_correlation(correlation_id)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Add correlation ID to response headers
            response.headers[self.header_name] = correlation_id
            
            return response
        finally:
            # Clean up logging context
            set_correlation_id(None)
            unbind_context("correlation_id")


def get_correlation_id(request: Request) -> str:
    """Get the correlation ID from the request.
    
    Args:
        request: The current request.
    
    Returns:
        The correlation ID for this request.
    """
    return getattr(request.state, "correlation_id", generate_correlation_id())
