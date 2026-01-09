"""Base worker class with queue polling and job processing."""

import asyncio
import os
import signal
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from shared.config import get_settings
from shared.logging.config import (
    bind_context,
    configure_logging,
    get_logger,
    set_correlation_id,
    unbind_context,
)
from shared.queue.client import QueueClient, get_queue_client
from shared.telemetry import configure_telemetry, get_tracer
from shared.telemetry.config import (
    add_span_event,
    create_span_link_from_message,
    extract_trace_context,
    record_exception_on_span,
)
from shared.worker.health_server import WorkerHealthServer

T = TypeVar("T")


class WorkerStatus(str, Enum):
    """Worker processing status."""

    SUCCESS = "success"
    FAILED = "failed"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"
    RATE_LIMITED = "rate_limited"  # Infinite retry with long delays


@dataclass
class WorkerResult:
    """Result of processing a job."""

    status: WorkerStatus
    message: str | None = None
    error: Exception | None = None
    data: dict[str, Any] | None = None

    @classmethod
    def success(
        cls, message: str | None = None, data: dict[str, Any] | None = None
    ) -> "WorkerResult":
        """Create a success result."""
        return cls(status=WorkerStatus.SUCCESS, message=message, data=data)

    @classmethod
    def failed(cls, error: Exception, message: str | None = None) -> "WorkerResult":
        """Create a failed result."""
        return cls(status=WorkerStatus.FAILED, message=message or str(error), error=error)

    @classmethod
    def retry(cls, message: str | None = None) -> "WorkerResult":
        """Create a retry result."""
        return cls(status=WorkerStatus.RETRY, message=message)

    @classmethod
    def dead_letter(cls, message: str | None = None) -> "WorkerResult":
        """Create a dead letter result."""
        return cls(status=WorkerStatus.DEAD_LETTER, message=message)

    @classmethod
    def rate_limited(cls, message: str | None = None, retry_delay: int = 300) -> "WorkerResult":
        """Create a rate limited result (infinite retry with long delay).

        Args:
            message: Error message to display.
            retry_delay: Seconds before retry (default 5 minutes).
        """
        return cls(
            status=WorkerStatus.RATE_LIMITED, message=message, data={"retry_delay": retry_delay}
        )


class BaseWorker(ABC, Generic[T]):
    """Base class for queue workers with polling and processing logic.

    Subclasses must implement:
    - queue_name: property returning the queue name to poll
    - process_message: method to process a single message

    Optional overrides:
    - parse_message: convert raw message dict to typed payload
    - on_success: called after successful processing
    - on_failure: called after failed processing
    - on_dead_letter: called when max retries exceeded
    """

    def __init__(
        self,
        poll_interval: float = 1.0,
        batch_size: int = 1,
        visibility_timeout: int | None = None,
        max_retries: int | None = None,
        min_request_delay: float = 0.0,
        request_delay_jitter: float = 0.0,
        health_port: int | None = None,
    ):
        """Initialize the worker.

        Args:
            poll_interval: Seconds between queue polls when empty.
            batch_size: Number of messages to fetch per poll (1-32).
            visibility_timeout: Seconds to hide message while processing.
            max_retries: Maximum retry attempts before dead lettering.
            min_request_delay: Minimum seconds to wait after each request (rate limiting).
            request_delay_jitter: Random additional delay (0 to this value) to avoid patterns.
            health_port: Port for health/debug HTTP server. Uses HEALTH_PORT env var or default.
        """
        self.poll_interval = poll_interval
        self.batch_size = min(max(batch_size, 1), 32)
        self._settings = get_settings()
        self.visibility_timeout = visibility_timeout or self._settings.queue.visibility_timeout
        self.max_retries = max_retries or self._settings.queue.max_retries
        self.min_request_delay = min_request_delay
        self.request_delay_jitter = request_delay_jitter
        self._running = False
        self._queue_client: QueueClient | None = None
        self._logger = get_logger(self.__class__.__name__)

        # Health server port: parameter > env var > default (8090)
        self._health_port = health_port or int(os.environ.get("HEALTH_PORT", "8090"))
        self._health_server: WorkerHealthServer | None = None

        # Configure telemetry - service name comes from worker class name
        worker_name = self.__class__.__name__.lower().replace("worker", "-worker")
        configure_telemetry(f"yt-summarizer-{worker_name}")
        self._tracer = get_tracer(self.__class__.__name__)

    @property
    @abstractmethod
    def queue_name(self) -> str:
        """Return the name of the queue to poll."""
        ...

    @property
    def queue_client(self) -> QueueClient:
        """Get or create the queue client."""
        if self._queue_client is None:
            self._queue_client = get_queue_client()
        return self._queue_client

    def parse_message(self, raw_message: dict[str, Any]) -> T:
        """Parse raw message dict into typed payload.

        Override this method to convert the raw message to a typed object.
        Default implementation returns the raw dict.

        Args:
            raw_message: The decoded message dictionary.

        Returns:
            Parsed message payload.
        """
        return raw_message  # type: ignore

    @abstractmethod
    async def process_message(self, message: T, correlation_id: str) -> WorkerResult:
        """Process a single message.

        Args:
            message: The parsed message payload.
            correlation_id: Correlation ID for tracing.

        Returns:
            WorkerResult indicating success, failure, or retry.
        """
        ...

    async def on_success(self, message: T, result: WorkerResult) -> None:
        """Called after successful message processing.

        Args:
            message: The processed message.
            result: The processing result.
        """
        pass

    async def on_failure(self, message: T, result: WorkerResult, retry_count: int) -> None:
        """Called after failed message processing.

        Args:
            message: The failed message.
            result: The processing result.
            retry_count: Current retry count.
        """
        pass

    async def on_dead_letter(self, message: T, result: WorkerResult) -> None:
        """Called when message exceeds max retries.

        Args:
            message: The dead-lettered message.
            result: The processing result.
        """
        pass

    def get_additional_connectivity_checks(self) -> dict[str, Callable[[], bool]]:
        """Return additional connectivity checks for this worker.

        Override this method in subclasses that need additional dependency checks.
        For example, workers that use OpenAI can add the OpenAI check here.

        Returns:
            Dict mapping check name to check function.

        Example:
            def get_additional_connectivity_checks(self):
                return {"openai": self._check_openai_connectivity}
        """
        return {}

    def _check_queue_connectivity(self) -> bool:
        """Check if queue service is reachable.

        Used by health endpoint to determine worker health.
        """
        try:
            # Try to ensure queue exists - this validates connectivity
            self.queue_client.ensure_queue(self.queue_name)
            return True
        except Exception:
            return False

    def _check_database_connectivity(self) -> bool:
        """Check if database is reachable.

        Used by health endpoint to determine worker health.
        """
        try:
            import asyncio

            from shared.db.connection import get_db

            # Run async connect in sync context
            db = get_db()
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(db.connect())
                return True
            finally:
                loop.close()
        except Exception:
            return False

    def _check_blob_connectivity(self) -> bool:
        """Check if blob storage is reachable.

        Used by health endpoint to determine worker health.
        """
        try:
            from shared.blob.client import get_connection_string

            # Verify connection string is available and valid
            conn_str = get_connection_string()
            return bool(conn_str)
        except Exception:
            return False

    def _check_openai_connectivity(self) -> bool:
        """Check if OpenAI (Azure or standard) is configured and reachable.

        Used by health endpoint for workers that depend on LLM inference.
        Only checks configuration - does not make API calls.
        """
        try:
            from shared.config import get_settings

            settings = get_settings()
            openai_settings = settings.openai

            # Check if Azure OpenAI is configured
            if openai_settings.is_azure_configured:
                return True

            # Check if standard OpenAI is configured
            if openai_settings.api_key and openai_settings.api_key != "not-configured":
                return True

            # No OpenAI configuration found
            return False
        except Exception:
            return False

    async def _process_single_message(
        self,
        queue_message: Any,
        raw_message: dict[str, Any],
    ) -> None:
        """Process a single message from the queue.

        Args:
            queue_message: The raw queue message object.
            raw_message: The decoded message dictionary.
        """
        correlation_id = raw_message.get("correlation_id", "unknown")
        retry_count = raw_message.get("retry_count", 0)

        # Set logging context
        set_correlation_id(correlation_id)
        bind_context(
            correlation_id=correlation_id,
            queue=self.queue_name,
            retry_count=retry_count,
        )

        # Extract trace context from message if available (for distributed tracing)
        parent_context = extract_trace_context(raw_message)

        # Create a span link to the producer span for better trace visualization
        # Links show the relationship between producer and consumer spans even
        # when they share the same parent context
        span_link = create_span_link_from_message(raw_message)
        links = [span_link] if span_link else []

        # Start a trace span for message processing (linked to parent if available)
        with self._tracer.start_as_current_span(
            f"process_{self.queue_name}",
            context=parent_context,
            links=links,
            attributes={
                "messaging.system": "azure_storage_queue",
                "messaging.destination": self.queue_name,
                "messaging.operation": "process",
                "messaging.message.correlation_id": correlation_id,
                "messaging.message.retry_count": retry_count,
                "worker.class": self.__class__.__name__,
            },
        ) as span:
            try:
                # Add event: message received
                add_span_event(
                    span,
                    "message_received",
                    {
                        "queue": self.queue_name,
                        "correlation_id": correlation_id,
                        "retry_count": retry_count,
                    },
                )

                # Parse message
                try:
                    message = self.parse_message(raw_message)
                    # Add video_id to span if available
                    if hasattr(message, "video_id"):
                        span.set_attribute("video.id", str(message.video_id))
                    if hasattr(message, "job_id"):
                        span.set_attribute("job.id", str(message.job_id))

                    # Add event: message parsed successfully
                    add_span_event(
                        span,
                        "message_parsed",
                        {
                            "video_id": str(getattr(message, "video_id", "unknown")),
                            "job_id": str(getattr(message, "job_id", "unknown")),
                        },
                    )
                except Exception as e:
                    self._logger.error("Failed to parse message", error=str(e))
                    record_exception_on_span(span, e, {"phase": "message_parsing"})
                    # Delete malformed messages
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    add_span_event(span, "message_deleted", {"reason": "parse_error"})
                    return

                # Process message
                self._logger.info("Processing message")
                add_span_event(span, "processing_started")
                start_time = datetime.utcnow()

                try:
                    result = await self.process_message(message, correlation_id)
                except Exception as e:
                    self._logger.exception("Unhandled exception during processing")
                    result = WorkerResult.failed(e)
                    record_exception_on_span(span, e, {"phase": "message_processing"})

                elapsed = (datetime.utcnow() - start_time).total_seconds()
                span.set_attribute("processing.duration_seconds", elapsed)
                span.set_attribute("processing.status", result.status.value)

                # Add event: processing completed
                add_span_event(
                    span,
                    "processing_completed",
                    {
                        "status": result.status.value,
                        "duration_seconds": elapsed,
                        "message": result.message or "",
                    },
                )

                self._logger.info(
                    "Processing complete", elapsed_seconds=elapsed, status=result.status.value
                )

                # Handle result
                if result.status == WorkerStatus.SUCCESS:
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    add_span_event(span, "message_acknowledged", {"outcome": "success"})
                    await self.on_success(message, result)

                elif result.status == WorkerStatus.RETRY:
                    # Let message become visible again for retry
                    # Don't delete - visibility timeout will expire
                    add_span_event(
                        span,
                        "message_retry_scheduled",
                        {
                            "outcome": "retry",
                            "retry_count": retry_count,
                        },
                    )
                    await self.on_failure(message, result, retry_count)

                elif result.status == WorkerStatus.FAILED:
                    if retry_count >= self.max_retries:
                        self._logger.error("Max retries exceeded, dead lettering")
                        span.set_attribute("dead_lettered", True)
                        add_span_event(
                            span,
                            "message_dead_lettered",
                            {
                                "reason": "max_retries_exceeded",
                                "retry_count": retry_count,
                                "max_retries": self.max_retries,
                            },
                        )
                        self.queue_client.delete_message(self.queue_name, queue_message)
                        await self.on_dead_letter(message, result)
                    else:
                        # Requeue with incremented retry count
                        raw_message["retry_count"] = retry_count + 1
                        visibility_timeout = min(60 * (2**retry_count), 3600)
                        self.queue_client.send_message(
                            self.queue_name,
                            raw_message,
                            visibility_timeout=visibility_timeout,
                        )
                        self.queue_client.delete_message(self.queue_name, queue_message)
                        add_span_event(
                            span,
                            "message_requeued",
                            {
                                "outcome": "retry",
                                "new_retry_count": retry_count + 1,
                                "visibility_timeout_seconds": visibility_timeout,
                            },
                        )
                        await self.on_failure(message, result, retry_count + 1)

                elif result.status == WorkerStatus.DEAD_LETTER:
                    span.set_attribute("dead_lettered", True)
                    add_span_event(
                        span,
                        "message_dead_lettered",
                        {
                            "reason": "worker_requested",
                        },
                    )
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    await self.on_dead_letter(message, result)

                elif result.status == WorkerStatus.RATE_LIMITED:
                    # Infinite retry with long delays - don't increment retry_count for rate limits
                    retry_delay = result.data.get("retry_delay", 300) if result.data else 300
                    # Cap at 1 hour between retries
                    retry_delay = min(retry_delay, 3600)
                    span.set_attribute("rate_limited", True)
                    span.set_attribute("rate_limit.retry_delay_seconds", retry_delay)

                    add_span_event(
                        span,
                        "rate_limit_detected",
                        {
                            "retry_delay_seconds": retry_delay,
                            "message": result.message or "Rate limited",
                        },
                    )

                    self._logger.warning(
                        "Rate limited, will retry",
                        retry_delay_seconds=retry_delay,
                        message=result.message,
                    )
                    # Requeue with same retry_count (doesn't count toward max_retries)
                    self.queue_client.send_message(
                        self.queue_name,
                        raw_message,
                        visibility_timeout=retry_delay,
                    )
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    await self.on_failure(message, result, retry_count)

            finally:
                set_correlation_id(None)
                unbind_context("correlation_id", "queue", "retry_count")

    async def poll_once(self) -> int:
        """Poll the queue once and process any messages.

        Returns:
            Number of messages processed.
        """
        import random

        messages = self.queue_client.receive_messages(
            self.queue_name,
            max_messages=self.batch_size,
            visibility_timeout=self.visibility_timeout,
        )

        for queue_message, raw_message in messages:
            await self._process_single_message(queue_message, raw_message)

            # Rate limiting: delay after each request to avoid hitting external API limits
            if self.min_request_delay > 0:
                delay = self.min_request_delay
                if self.request_delay_jitter > 0:
                    delay += random.uniform(0, self.request_delay_jitter)
                self._logger.debug("Rate limit delay", delay_seconds=delay)
                await asyncio.sleep(delay)

        return len(messages)

    async def run(self) -> None:
        """Run the worker loop.

        Polls the queue continuously until stopped.
        """
        self._running = True
        configure_logging(
            level=self._settings.logging.level,
            json_format=self._settings.logging.json_format,
            service_name=self.__class__.__name__,
        )

        # Start health server
        self._health_server = WorkerHealthServer(
            port=self._health_port,
            worker_name=self.__class__.__name__,
            queue_name=self.queue_name,
        )

        # Add connectivity checks for health endpoint
        self._health_server.add_connectivity_check("queue", self._check_queue_connectivity)
        self._health_server.add_connectivity_check("database", self._check_database_connectivity)
        self._health_server.add_connectivity_check("blob_storage", self._check_blob_connectivity)

        # Add any additional connectivity checks from subclass
        for name, check_fn in self.get_additional_connectivity_checks().items():
            self._health_server.add_connectivity_check(name, check_fn)

        self._health_server.start()
        self._logger.info(
            "Health server started",
            port=self._health_port,
            health_url=f"http://localhost:{self._health_port}/health",
            debug_url=f"http://localhost:{self._health_port}/debug",
        )

        self._logger.info(
            "Worker starting",
            queue=self.queue_name,
            poll_interval=self.poll_interval,
            batch_size=self.batch_size,
            visibility_timeout=self.visibility_timeout,
            max_retries=self.max_retries,
        )

        # Ensure queue exists
        self.queue_client.ensure_queue(self.queue_name)

        while self._running:
            try:
                processed = await self.poll_once()

                if processed == 0:
                    # No messages, wait before polling again
                    await asyncio.sleep(self.poll_interval)

            except Exception:
                self._logger.exception("Error during poll loop")
                await asyncio.sleep(self.poll_interval * 2)  # Back off on errors

        # Stop health server
        if self._health_server:
            self._health_server.stop()

        self._logger.info("Worker stopped")

    def stop(self) -> None:
        """Stop the worker loop."""
        self._logger.info("Stopping worker")
        self._running = False

    def setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def handle_signal(signum: int, frame: Any) -> None:
            self._logger.info("Received signal", signal=signum)
            self.stop()

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)


def run_worker(worker: BaseWorker) -> None:
    """Run a worker as the main entry point.

    Args:
        worker: The worker instance to run.
    """
    worker.setup_signal_handlers()

    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        pass
    finally:
        sys.exit(0)
