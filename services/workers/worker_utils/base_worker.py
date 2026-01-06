"""Base worker class with queue polling and job processing."""

import asyncio
import signal
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

# Import shared modules (path will be configured via PYTHONPATH)
try:
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
    from shared.telemetry.config import extract_trace_context
except ImportError:
    # Fallback for development without shared package installed
    import logging
    
    def get_settings():
        class MockSettings:
            service_name = "yt-summarizer-worker"
            class logging:
                level = "INFO"
                json_format = False
            class queue:
                visibility_timeout = 300
                max_retries = 5
        return MockSettings()
    
    def configure_logging(*args, **kwargs):
        pass
    
    def get_logger(name):
        return logging.getLogger(name)
    
    def bind_context(**kwargs):
        pass
    
    def unbind_context(*args):
        pass
    
    def set_correlation_id(cid):
        pass
    
    def get_queue_client():
        raise NotImplementedError("Queue client not available")
    
    def configure_telemetry(service_name, **kwargs):
        return False
    
    def get_tracer(name):
        from shared.telemetry.config import NoOpTracer
        return NoOpTracer()
    
    def extract_trace_context(message):
        return None


T = TypeVar("T")


class WorkerStatus(str, Enum):
    """Worker processing status."""
    
    SUCCESS = "success"
    FAILED = "failed"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


@dataclass
class WorkerResult:
    """Result of processing a job."""
    
    status: WorkerStatus
    message: str | None = None
    error: Exception | None = None
    data: dict[str, Any] | None = None
    
    @classmethod
    def success(cls, message: str | None = None, data: dict[str, Any] | None = None) -> "WorkerResult":
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
    ):
        """Initialize the worker.
        
        Args:
            poll_interval: Seconds between queue polls when empty.
            batch_size: Number of messages to fetch per poll (1-32).
            visibility_timeout: Seconds to hide message while processing.
            max_retries: Maximum retry attempts before dead lettering.
        """
        self.poll_interval = poll_interval
        self.batch_size = min(max(batch_size, 1), 32)
        self._settings = get_settings()
        self.visibility_timeout = visibility_timeout or self._settings.queue.visibility_timeout
        self.max_retries = max_retries or self._settings.queue.max_retries
        self._running = False
        self._queue_client: QueueClient | None = None
        self._logger = get_logger(self.__class__.__name__)
        
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
        
        # Start a trace span for message processing (linked to parent if available)
        with self._tracer.start_as_current_span(
            f"process_{self.queue_name}",
            context=parent_context,
            attributes={
                "messaging.system": "azure_storage_queue",
                "messaging.destination": self.queue_name,
                "messaging.message.correlation_id": correlation_id,
                "messaging.message.retry_count": retry_count,
                "worker.class": self.__class__.__name__,
            },
        ) as span:
            try:
                # Parse message
                try:
                    message = self.parse_message(raw_message)
                    # Add video_id to span if available
                    if hasattr(message, "video_id"):
                        span.set_attribute("video.id", message.video_id)
                    if hasattr(message, "job_id"):
                        span.set_attribute("job.id", str(message.job_id))
                except Exception as e:
                    self._logger.error("Failed to parse message", error=str(e))
                    span.set_attribute("error", True)
                    span.set_attribute("error.message", str(e))
                    # Delete malformed messages
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    return
                
                # Process message
                self._logger.info("Processing message")
                start_time = datetime.utcnow()
                
                try:
                    result = await self.process_message(message, correlation_id)
                except Exception as e:
                    self._logger.exception("Unhandled exception during processing")
                    result = WorkerResult.failed(e)
                    span.set_attribute("error", True)
                    span.set_attribute("error.message", str(e))
                
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                span.set_attribute("processing.duration_seconds", elapsed)
                span.set_attribute("processing.status", result.status.value)
                self._logger.info("Processing complete", elapsed_seconds=elapsed, status=result.status.value)
                
                # Handle result
                if result.status == WorkerStatus.SUCCESS:
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    await self.on_success(message, result)
                    
                elif result.status == WorkerStatus.RETRY:
                    # Let message become visible again for retry
                    # Don't delete - visibility timeout will expire
                    await self.on_failure(message, result, retry_count)
                    
                elif result.status == WorkerStatus.FAILED:
                    if retry_count >= self.max_retries:
                        self._logger.error("Max retries exceeded, dead lettering")
                        span.set_attribute("dead_lettered", True)
                        self.queue_client.delete_message(self.queue_name, queue_message)
                        await self.on_dead_letter(message, result)
                    else:
                        # Requeue with incremented retry count
                        raw_message["retry_count"] = retry_count + 1
                        self.queue_client.send_message(
                            self.queue_name,
                            raw_message,
                            visibility_timeout=min(60 * (2 ** retry_count), 3600),  # Exponential backoff
                        )
                        self.queue_client.delete_message(self.queue_name, queue_message)
                        await self.on_failure(message, result, retry_count + 1)
                        
                elif result.status == WorkerStatus.DEAD_LETTER:
                    span.set_attribute("dead_lettered", True)
                    self.queue_client.delete_message(self.queue_name, queue_message)
                    await self.on_dead_letter(message, result)
                    
            finally:
                set_correlation_id(None)
                unbind_context("correlation_id", "queue", "retry_count")
    
    async def poll_once(self) -> int:
        """Poll the queue once and process any messages.
        
        Returns:
            Number of messages processed.
        """
        messages = self.queue_client.receive_messages(
            self.queue_name,
            max_messages=self.batch_size,
            visibility_timeout=self.visibility_timeout,
        )
        
        for queue_message, raw_message in messages:
            await self._process_single_message(queue_message, raw_message)
        
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
                    
            except Exception as e:
                self._logger.exception("Error during poll loop")
                await asyncio.sleep(self.poll_interval * 2)  # Back off on errors
        
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
