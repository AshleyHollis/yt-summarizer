"""Correlation ID middleware for request tracing."""

import uuid
from typing import Callable

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


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware to handle correlation IDs for request tracing.
    
    This middleware:
    1. Extracts correlation ID from incoming request headers
    2. Generates a new one if not present
    3. Adds it to the response headers
    4. Makes it available throughout the request lifecycle
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
