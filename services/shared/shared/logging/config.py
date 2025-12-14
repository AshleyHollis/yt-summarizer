"""Structured logging configuration with structlog."""

import logging
import os
import sys
from typing import Any

import structlog
from structlog.types import Processor

# Context variable for correlation ID
_correlation_id_var: str | None = None


def get_correlation_id() -> str | None:
    """Get the current correlation ID."""
    return _correlation_id_var


def set_correlation_id(correlation_id: str | None) -> None:
    """Set the current correlation ID."""
    global _correlation_id_var
    _correlation_id_var = correlation_id


def add_correlation_id(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add correlation ID to log events."""
    correlation_id = get_correlation_id()
    if correlation_id:
        event_dict["correlation_id"] = correlation_id
    return event_dict


def add_service_info(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add service name and version to log events."""
    service_name = os.environ.get("SERVICE_NAME", "yt-summarizer")
    service_version = os.environ.get("SERVICE_VERSION", "0.1.0")
    event_dict["service"] = service_name
    event_dict["version"] = service_version
    return event_dict


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    service_name: str | None = None,
) -> None:
    """Configure structured logging for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: If True, output JSON logs. If False, use console format.
        service_name: Name of the service for log context.
    """
    # Set service name in environment if provided
    if service_name:
        os.environ["SERVICE_NAME"] = service_name
    
    # Configure log level from environment or parameter
    log_level = os.environ.get("LOG_LEVEL", level).upper()
    
    # Common processors
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        add_correlation_id,
        add_service_info,
    ]
    
    # Format-specific processors
    if json_format:
        # Production: JSON output
        processors: list[Processor] = [
            *shared_processors,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
        
        # Configure standard logging to use structlog
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, log_level),
        )
    else:
        # Development: Console output with colors
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        ]
        
        # Configure standard logging
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, log_level),
        )
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.
    
    Args:
        name: Logger name (usually __name__).
    
    Returns:
        A bound structlog logger.
    """
    return structlog.get_logger(name)


class LogContext:
    """Context manager for adding temporary log context."""
    
    def __init__(self, **kwargs: Any):
        """Initialize with context values to add.
        
        Args:
            **kwargs: Key-value pairs to add to log context.
        """
        self._context = kwargs
        self._token: Any = None
    
    def __enter__(self) -> "LogContext":
        """Enter the context, binding values to structlog context."""
        self._token = structlog.contextvars.bind_contextvars(**self._context)
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the context, unbinding values."""
        structlog.contextvars.unbind_contextvars(*self._context.keys())


def bind_context(**kwargs: Any) -> None:
    """Bind values to the current logging context.
    
    Args:
        **kwargs: Key-value pairs to add to log context.
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def unbind_context(*keys: str) -> None:
    """Unbind values from the current logging context.
    
    Args:
        *keys: Keys to remove from log context.
    """
    structlog.contextvars.unbind_contextvars(*keys)


def clear_context() -> None:
    """Clear all values from the current logging context."""
    structlog.contextvars.clear_contextvars()
