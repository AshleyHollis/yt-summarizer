"""Progress emitter for AG-UI state streaming.

This module provides utilities for emitting structured progress updates
via AG-UI STATE_DELTA events. Used by backend tools to stream multi-step
workflow progress to the frontend.

Usage:
    async with ProgressEmitter(event_sink, "import-workflow", 5) as progress:
        await progress.start_step("validate", "Validating input")
        # ... do work ...
        await progress.complete_step()

        await progress.start_step("fetch", "Fetching data")
        # ... do work ...
        await progress.complete_step(result={"count": 10})
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol


class WorkflowStatus(str, Enum):
    """Status of a workflow execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class StepInfo:
    """Information about the currently executing step."""

    name: str
    description: str
    started_at: str  # ISO timestamp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CompletedStep:
    """Information about a completed step."""

    name: str
    completed_at: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorInfo:
    """Error information for failed workflows."""

    code: str
    message: str
    retryable: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowProgress:
    """Workflow progress state - matches frontend TypeScript schema."""

    workflow_id: str
    step: int
    total_steps: int
    percent: float
    message: str
    status: WorkflowStatus
    current_step: StepInfo | None = None
    completed_steps: list[CompletedStep] = field(default_factory=list)
    error: ErrorInfo | None = None
    result: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization (camelCase for frontend)."""
        return {
            "workflowId": self.workflow_id,
            "step": self.step,
            "totalSteps": self.total_steps,
            "percent": self.percent,
            "message": self.message,
            "status": self.status.value,
            "currentStep": self.current_step.to_dict() if self.current_step else None,
            "completedSteps": [s.to_dict() for s in self.completed_steps],
            "error": self.error.to_dict() if self.error else None,
            "result": self.result,
        }


class EventSink(Protocol):
    """Protocol for emitting AG-UI events."""

    async def emit_state_delta(self, delta: dict[str, Any]) -> None:
        """Emit a STATE_DELTA event with partial state update."""
        ...


class ProgressEmitter:
    """Emits workflow progress via AG-UI STATE_DELTA events.

    This class manages workflow progress state and emits updates
    to the frontend via the AG-UI protocol.

    Example usage with async context manager:
        async with ProgressEmitter(sink, "my-workflow", 3) as progress:
            await progress.start_step("step1", "Starting...")
            # do work
            await progress.complete_step()

    Example usage without context manager:
        emitter = ProgressEmitter(sink, "my-workflow", 3)
        await emitter.initialize()
        try:
            await emitter.start_step("step1", "Starting...")
            # do work
            await emitter.complete_step()
            await emitter.finalize()
        except Exception as e:
            await emitter.fail(str(e))
    """

    def __init__(
        self,
        event_sink: EventSink,
        workflow_id: str | None = None,
        total_steps: int = 1,
        initial_message: str = "Starting...",
    ):
        """Initialize the progress emitter.

        Args:
            event_sink: The sink to emit AG-UI events to.
            workflow_id: Unique ID for this workflow (auto-generated if not provided).
            total_steps: Total number of steps in the workflow.
            initial_message: Initial status message.
        """
        self.event_sink = event_sink
        self.workflow_id = workflow_id or str(uuid.uuid4())
        self.total_steps = total_steps
        self._step_start_time: float | None = None

        self.progress = WorkflowProgress(
            workflow_id=self.workflow_id,
            step=0,
            total_steps=total_steps,
            percent=0,
            message=initial_message,
            status=WorkflowStatus.PENDING,
        )

    async def __aenter__(self) -> ProgressEmitter:
        """Enter async context - emit initial state."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit async context - finalize or fail based on exception."""
        if exc_type is not None:
            # An exception occurred - mark as failed
            error_message = str(exc_val) if exc_val else "Unknown error"
            await self.fail(error_message, code=exc_type.__name__)
            return False  # Don't suppress the exception
        else:
            # No exception - finalize if not already completed
            if self.progress.status == WorkflowStatus.RUNNING:
                await self.finalize()
            return False

    async def initialize(self) -> None:
        """Initialize the workflow and emit starting state."""
        self.progress.status = WorkflowStatus.RUNNING
        await self._emit()

    async def start_step(
        self, step_name: str, description: str, message: str | None = None
    ) -> None:
        """Start a new step in the workflow.

        Args:
            step_name: Unique identifier for the step.
            description: Human-readable description.
            message: Optional status message (defaults to description).
        """
        # Complete previous step if there was one
        if self.progress.current_step and self._step_start_time:
            duration_ms = int((time.time() - self._step_start_time) * 1000)
            self.progress.completed_steps.append(
                CompletedStep(
                    name=self.progress.current_step.name,
                    completed_at=datetime.utcnow().isoformat() + "Z",
                    duration_ms=duration_ms,
                )
            )

        # Start new step
        self.progress.step += 1
        self.progress.percent = round((self.progress.step / self.total_steps) * 100)
        self.progress.message = message or description
        self.progress.current_step = StepInfo(
            name=step_name,
            description=description,
            started_at=datetime.utcnow().isoformat() + "Z",
        )
        self._step_start_time = time.time()

        await self._emit()

    async def update_message(self, message: str) -> None:
        """Update the current step's message without advancing.

        Args:
            message: New status message.
        """
        self.progress.message = message
        await self._emit()

    async def update_percent(self, percent: float) -> None:
        """Update the progress percentage.

        Args:
            percent: New percentage (0-100).
        """
        self.progress.percent = min(max(percent, 0), 100)
        await self._emit()

    async def complete_step(self, message: str | None = None) -> None:
        """Complete the current step.

        Args:
            message: Optional completion message.
        """
        if self.progress.current_step and self._step_start_time:
            duration_ms = int((time.time() - self._step_start_time) * 1000)
            self.progress.completed_steps.append(
                CompletedStep(
                    name=self.progress.current_step.name,
                    completed_at=datetime.utcnow().isoformat() + "Z",
                    duration_ms=duration_ms,
                )
            )
            self.progress.current_step = None
            self._step_start_time = None

        if message:
            self.progress.message = message

        await self._emit()

    async def finalize(self, result: Any = None, message: str = "Completed successfully") -> None:
        """Finalize the workflow as completed.

        Args:
            result: Optional result data.
            message: Completion message.
        """
        # Complete any remaining step
        await self.complete_step()

        self.progress.status = WorkflowStatus.COMPLETED
        self.progress.percent = 100
        self.progress.step = self.total_steps
        self.progress.message = message
        self.progress.result = result

        await self._emit()

    async def fail(self, message: str, code: str = "ERROR", retryable: bool = True) -> None:
        """Mark the workflow as failed.

        Args:
            message: Error message.
            code: Error code.
            retryable: Whether the operation can be retried.
        """
        self.progress.status = WorkflowStatus.FAILED
        self.progress.message = message
        self.progress.error = ErrorInfo(
            code=code,
            message=message,
            retryable=retryable,
        )

        await self._emit()

    async def cancel(self, message: str = "Cancelled by user") -> None:
        """Mark the workflow as cancelled.

        Args:
            message: Cancellation message.
        """
        self.progress.status = WorkflowStatus.CANCELLED
        self.progress.message = message

        await self._emit()

    async def _emit(self) -> None:
        """Emit the current progress state as a STATE_DELTA event."""
        delta = {"workflowProgress": self.progress.to_dict()}
        await self.event_sink.emit_state_delta(delta)


class SimpleEventSink:
    """Simple event sink that collects events for testing or synchronous use.

    Use this for testing or when you need to collect events before
    sending them as a batch.
    """

    def __init__(self):
        self.events: list[dict[str, Any]] = []

    async def emit_state_delta(self, delta: dict[str, Any]) -> None:
        """Collect STATE_DELTA event."""
        self.events.append(
            {
                "type": "STATE_DELTA",
                "delta": delta,
            }
        )

    def get_events(self) -> list[dict[str, Any]]:
        """Get all collected events."""
        return self.events

    def clear(self) -> None:
        """Clear collected events."""
        self.events = []
