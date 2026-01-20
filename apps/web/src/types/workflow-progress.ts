/**
 * Shared workflow progress types for AG-UI integration.
 *
 * Used by both Pattern A (frontend-initiated) and Pattern B (backend-initiated)
 * workflows to provide consistent progress tracking and UI rendering.
 */

/**
 * Status of a workflow execution
 */
export type WorkflowStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Information about the currently executing step
 */
export interface StepInfo {
  /** Step identifier/name */
  name: string;
  /** Human-readable description */
  description: string;
  /** ISO timestamp when step started */
  startedAt: string;
}

/**
 * Information about a completed step
 */
export interface CompletedStep {
  /** Step identifier/name */
  name: string;
  /** ISO timestamp when step completed */
  completedAt: string;
  /** Duration in milliseconds */
  durationMs: number;
}

/**
 * Error information for failed workflows
 */
export interface WorkflowError {
  /** Error code for programmatic handling */
  code: string;
  /** Human-readable error message */
  message: string;
  /** Whether the operation can be retried */
  retryable: boolean;
}

/**
 * Workflow progress state - shared between frontend and backend.
 *
 * This schema is used for:
 * 1. AG-UI STATE_DELTA events streamed from backend tools
 * 2. React state in frontend progress components
 * 3. Database persistence for resumable workflows
 */
export interface WorkflowProgress {
  /** Unique workflow/job ID */
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
  status: WorkflowStatus;

  /** Current step details (optional) */
  currentStep?: StepInfo;

  /** List of completed steps (optional) */
  completedSteps?: CompletedStep[];

  /** Error information if failed (optional) */
  error?: WorkflowError;

  /** Workflow result on completion (optional) */
  result?: unknown;
}

/**
 * Progress update - partial update to workflow progress.
 * Used for incremental STATE_DELTA events.
 */
export type WorkflowProgressUpdate = Partial<WorkflowProgress> & {
  workflowId: string;
};

/**
 * AG-UI state shape that includes workflow progress.
 * The agent can include this in STATE_DELTA events.
 */
export interface AgentState {
  /** Active workflow progress (if any) */
  workflowProgress?: WorkflowProgress;

  /** Additional custom state fields */
  [key: string]: unknown;
}

/**
 * Helper to create initial progress state
 */
export function createInitialProgress(
  workflowId: string,
  totalSteps: number,
  initialMessage: string = 'Starting...'
): WorkflowProgress {
  return {
    workflowId,
    step: 0,
    totalSteps,
    percent: 0,
    message: initialMessage,
    status: 'pending',
  };
}

/**
 * Helper to update progress for next step
 */
export function advanceProgress(
  current: WorkflowProgress,
  stepName: string,
  stepDescription: string,
  message: string
): WorkflowProgress {
  const newStep = current.step + 1;
  const percent = Math.round((newStep / current.totalSteps) * 100);

  const completedSteps: CompletedStep[] = [...(current.completedSteps || [])];

  // Complete the previous step if there was one
  if (current.currentStep) {
    completedSteps.push({
      name: current.currentStep.name,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - new Date(current.currentStep.startedAt).getTime(),
    });
  }

  return {
    ...current,
    step: newStep,
    percent,
    message,
    status: 'running',
    currentStep: {
      name: stepName,
      description: stepDescription,
      startedAt: new Date().toISOString(),
    },
    completedSteps,
  };
}

/**
 * Helper to mark progress as completed
 */
export function completeProgress<T>(
  current: WorkflowProgress,
  result: T,
  message: string = 'Completed successfully'
): WorkflowProgress {
  const completedSteps: CompletedStep[] = [...(current.completedSteps || [])];

  // Complete the final step if there was one
  if (current.currentStep) {
    completedSteps.push({
      name: current.currentStep.name,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - new Date(current.currentStep.startedAt).getTime(),
    });
  }

  return {
    ...current,
    step: current.totalSteps,
    percent: 100,
    message,
    status: 'completed',
    currentStep: undefined,
    completedSteps,
    result,
  };
}

/**
 * Helper to mark progress as failed
 */
export function failProgress(current: WorkflowProgress, error: WorkflowError): WorkflowProgress {
  return {
    ...current,
    status: 'failed',
    message: error.message,
    error,
  };
}
