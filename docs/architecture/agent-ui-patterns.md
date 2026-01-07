# Agent UI Patterns: Frontend-Initiated vs Backend-Initiated Workflows

This document defines two architectural patterns for building rich, interactive agent workflows with Microsoft Agent Framework, AG-UI, and CopilotKit.

## Overview

We support two distinct patterns to cleanly separate concerns while preserving rich frontend interactivity:

| Pattern | Description | Initiator | Progress Source |
|---------|-------------|-----------|-----------------|
| **Pattern A** | Frontend-initiated UI + Backend streaming work | Frontend tool renders UI first | Backend streams progress via AG-UI state |
| **Pattern B** | Backend-initiated work with frontend rendering | Backend tool does work | Frontend renders via AG-UI events |

---

## Pattern A — Frontend-Initiated UI + Backend Streaming Work

### When to Use
- **User-driven flows**: Wizards, confirmations, multi-step forms
- **User input required before processing**: File uploads, configuration, selections
- **Interactive progress panels**: The user needs to see and interact with progress

### Flow Diagram
```
┌──────────────────────────────────────────────────────────────────────┐
│                        PATTERN A FLOW                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Agent calls frontend tool                                        │
│     ┌─────────────┐                                                  │
│     │ show_wizard │ ─────> Frontend renders wizard/modal            │
│     └─────────────┘                                                  │
│                                                                      │
│  2. Frontend tool collects user input                                │
│     ┌─────────────┐                                                  │
│     │   User      │ ─────> Fills form, confirms action              │
│     │   Input     │                                                  │
│     └─────────────┘                                                  │
│                                                                      │
│  3. Frontend tool returns, agent calls backend tool                  │
│     ┌─────────────────────┐                                          │
│     │ process_batch_job   │ ─────> Backend starts work              │
│     └─────────────────────┘                                          │
│                                                                      │
│  4. Backend streams progress via AG-UI state                         │
│     ┌─────────────────────┐      ┌────────────────────────┐         │
│     │  STATE_DELTA        │ ───> │ Progress Bar Component │         │
│     │  { progress: 50% }  │      │ renders live updates   │         │
│     └─────────────────────┘      └────────────────────────┘         │
│                                                                      │
│  5. Backend completes, frontend shows success                        │
│     ┌─────────────────────┐                                          │
│     │ TOOL_CALL_RESULT    │ ─────> Success UI displayed             │
│     └─────────────────────┘                                          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Characteristics
- Frontend tool renders the initial UI (modal, wizard, panel)
- User interaction happens in the frontend tool's rendered component
- Backend tool receives validated input from the frontend tool's result
- Progress is streamed via AG-UI `STATE_DELTA` events
- Frontend renders progress using a shared `WorkflowProgress` component

---

## Pattern B — Backend-Initiated Work with Frontend Rendering

### When to Use
- **Automated agent workflows**: Agent decides to process without user input
- **Read-heavy operations**: Search, summarization, analysis
- **Quick operations**: Operations completing in < 5 seconds
- **Background processing**: Tasks that continue if browser disconnects

### Flow Diagram
```
┌──────────────────────────────────────────────────────────────────────┐
│                        PATTERN B FLOW                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Agent directly calls backend tool                                │
│     ┌───────────────────┐                                            │
│     │ search_videos     │ ─────> Backend starts processing          │
│     └───────────────────┘                                            │
│                                                                      │
│  2. Backend emits TOOL_CALL_START                                    │
│     ┌───────────────────┐      ┌─────────────────────────┐          │
│     │ TOOL_CALL_START   │ ───> │ Frontend useCopilotAction │        │
│     │ {tool: "search"}  │      │ render: Loading UI...    │          │
│     └───────────────────┘      └─────────────────────────┘          │
│                                                                      │
│  3. Backend streams STATE_DELTA for progress                         │
│     ┌───────────────────┐      ┌─────────────────────────┐          │
│     │ STATE_DELTA       │ ───> │ Progress component      │          │
│     │ {step: 2/5}       │      │ updates reactively      │          │
│     └───────────────────┘      └─────────────────────────┘          │
│                                                                      │
│  4. Backend emits TOOL_CALL_RESULT                                   │
│     ┌───────────────────┐      ┌─────────────────────────┐          │
│     │ TOOL_CALL_RESULT  │ ───> │ useCopilotAction        │          │
│     │ {videos: [...]}   │      │ render: Results UI      │          │
│     └───────────────────┘      └─────────────────────────┘          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Characteristics
- Backend tool is called directly by the agent
- Frontend uses `useCopilotAction` with `available: "disabled"` for render-only
- Progress comes from AG-UI `STATE_DELTA` events
- Frontend reacts to tool lifecycle (`inProgress`, `executing`, `complete`)
- Results are rendered using the tool's `render` function

---

## Pattern Selection Guidelines

| Scenario | Pattern | Reason |
|----------|---------|--------|
| Import wizard with file selection | **A** | User must select files first |
| Batch processing with confirmation | **A** | User must confirm before starting |
| Search videos | **B** | Agent decides, no input needed |
| Get library statistics | **B** | Quick operation, no input |
| Channel ingest with progress | **A** | User initiates, needs progress UI |
| Multi-step analysis | **B** | Agent orchestrates, streams updates |
| Configuration modal | **A** | User must fill form |
| Background indexing | **B** | Continues if browser disconnects |

---

## Shared Progress State Schema

Both patterns use the same progress state schema for consistency:

```typescript
// Shared progress state schema
interface WorkflowProgress {
  /** Unique workflow ID */
  workflowId: string;
  
  /** Current step number (1-based) */
  step: number;
  
  /** Total number of steps */
  totalSteps: number;
  
  /** Completion percentage (0-100) */
  percent: number;
  
  /** Human-readable message for current step */
  message: string;
  
  /** Workflow status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  
  /** Optional: Current step details */
  currentStep?: {
    name: string;
    description: string;
    startedAt: string; // ISO timestamp
  };
  
  /** Optional: List of completed steps */
  completedSteps?: Array<{
    name: string;
    completedAt: string;
    durationMs: number;
  }>;
  
  /** Optional: Error information if failed */
  error?: {
    code: string;
    message: string;
    retryable: boolean;
  };
  
  /** Optional: Workflow result (on completion) */
  result?: unknown;
}
```

Python equivalent:
```python
from dataclasses import dataclass
from typing import Optional, Any
from enum import Enum

class WorkflowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class StepInfo:
    name: str
    description: str
    started_at: str  # ISO timestamp

@dataclass
class CompletedStep:
    name: str
    completed_at: str
    duration_ms: int

@dataclass
class ErrorInfo:
    code: str
    message: str
    retryable: bool

@dataclass
class WorkflowProgress:
    workflow_id: str
    step: int
    total_steps: int
    percent: float
    message: str
    status: WorkflowStatus
    current_step: Optional[StepInfo] = None
    completed_steps: Optional[list[CompletedStep]] = None
    error: Optional[ErrorInfo] = None
    result: Optional[Any] = None
```

---

## Implementation Files

- **Types**: [apps/web/src/types/copilot-types.ts](../../apps/web/src/types/copilot-types.ts)
- **Workflow Progress Types**: [apps/web/src/types/workflow-progress.ts](../../apps/web/src/types/workflow-progress.ts)
- **Tool Loading Component**: [apps/web/src/components/copilot/ToolLoadingState.tsx](../../apps/web/src/components/copilot/ToolLoadingState.tsx)
- **Progress Panel Component**: [apps/web/src/components/copilot/WorkflowProgressPanel.tsx](../../apps/web/src/components/copilot/WorkflowProgressPanel.tsx)
- **Frontend Tools (Pattern A)**: [apps/web/src/hooks/useFrontendTools.tsx](../../apps/web/src/hooks/useFrontendTools.tsx)
- **Backend Renderers (Pattern B)**: [apps/web/src/hooks/useBackendToolRenderers.tsx](../../apps/web/src/hooks/useBackendToolRenderers.tsx)
- **Main Entry Point**: [apps/web/src/hooks/useCopilotActionsRefactored.tsx](../../apps/web/src/hooks/useCopilotActionsRefactored.tsx)
- **Backend Progress Emitter**: [services/api/src/api/agents/progress_emitter.py](../../services/api/src/api/agents/progress_emitter.py)

---

## Browser Disconnect Handling

Pattern B supports workflows that continue if the browser disconnects:

1. Backend tool saves workflow state to database
2. Progress is polled via REST API when reconnecting
3. WebSocket/SSE reconnection picks up streaming progress
4. Agent can report final status on next user interaction

Pattern A requires browser connection for the initial UI interaction but can use the same mechanisms for long-running backend work.

---

## Next Steps

1. Implement `WorkflowProgress` TypeScript types
2. Create `WorkflowProgressPanel` component
3. Add progress emitter to backend tools
4. Create example frontend tool (Pattern A)
5. Create example backend tool with progress (Pattern B)
6. Add AG-UI state delta streaming support
