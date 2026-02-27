'use client';

import { WorkflowProgress, WorkflowStatus } from '@/types/workflow-progress';
import { CheckCircle, XCircle, Clock, Loader2, AlertCircle } from 'lucide-react';
import { cn } from './copilotStyles';

interface WorkflowProgressPanelProps {
  /** Current progress state */
  progress: WorkflowProgress;

  /** Optional: Show step details */
  showSteps?: boolean;

  /** Optional: Compact mode */
  compact?: boolean;

  /** Optional: Custom class name */
  className?: string;

  /** Optional: Callback when retry is clicked (for failed states) */
  onRetry?: () => void;

  /** Optional: Callback when cancel is clicked */
  onCancel?: () => void;
}

const statusConfig: Record<
  WorkflowStatus,
  { icon: typeof CheckCircle; color: string; bgColor: string }
> = {
  pending: { icon: Clock, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10' },
  running: { icon: Loader2, color: 'text-blue-500', bgColor: 'bg-blue-500/10' },
  completed: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10' },
  failed: { icon: XCircle, color: 'text-red-500', bgColor: 'bg-red-500/10' },
  cancelled: { icon: AlertCircle, color: 'text-gray-500', bgColor: 'bg-gray-500/10' },
};

/**
 * WorkflowProgressPanel - Renders workflow progress for both Pattern A and Pattern B.
 *
 * Features:
 * - Progress bar with percentage
 * - Step counter
 * - Status icon
 * - Optional step timeline
 * - Error display with retry button
 */
export function WorkflowProgressPanel({
  progress,
  showSteps = false,
  compact = false,
  className,
  onRetry,
  onCancel,
}: WorkflowProgressPanelProps) {
  const config = statusConfig[progress.status];
  const StatusIcon = config.icon;
  const isAnimating = progress.status === 'running';

  if (compact) {
    return (
      <div
        className={cn(
          'flex items-center gap-3 py-2 px-3 rounded-lg border',
          'bg-[var(--copilot-kit-secondary-color)]/50',
          'border-[var(--copilot-kit-separator-color)]',
          className
        )}
      >
        <StatusIcon
          className={cn('w-4 h-4 flex-shrink-0', config.color, isAnimating && 'animate-spin')}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--copilot-kit-secondary-contrast-color)] truncate">
              {progress.message}
            </span>
            <span className="text-xs text-[var(--copilot-kit-muted-color)]">
              {progress.percent}%
            </span>
          </div>
          <div className="mt-1 h-1 bg-[var(--copilot-kit-separator-color)] rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full transition-all duration-300',
                progress.status === 'failed'
                  ? 'bg-red-500'
                  : 'bg-[var(--copilot-kit-primary-color)]'
              )}
              style={{ width: `${progress.percent}%` }}
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        'p-4 rounded-xl border',
        'bg-[var(--copilot-kit-secondary-color)]/50',
        'border-[var(--copilot-kit-separator-color)]',
        className
      )}
    >
      {/* Header */}
      <div className="flex items-start gap-3 mb-4">
        <div className={cn('p-2 rounded-lg flex-shrink-0', config.bgColor)}>
          <StatusIcon className={cn('w-5 h-5', config.color, isAnimating && 'animate-spin')} />
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-medium text-[var(--copilot-kit-secondary-contrast-color)]">
            {progress.message}
          </h4>
          <p className="text-xs text-[var(--copilot-kit-muted-color)] mt-0.5">
            Step {progress.step} of {progress.totalSteps}
          </p>
        </div>
        <div className="text-lg font-semibold text-[var(--copilot-kit-primary-color)]">
          {progress.percent}%
        </div>
      </div>

      {/* Progress Bar */}
      <div className="h-2 bg-[var(--copilot-kit-separator-color)] rounded-full overflow-hidden mb-4">
        <div
          className={cn(
            'h-full rounded-full transition-all duration-300',
            progress.status === 'failed' ? 'bg-red-500' : 'bg-[var(--copilot-kit-primary-color)]',
            isAnimating && 'animate-pulse'
          )}
          style={{ width: `${progress.percent}%` }}
        />
      </div>

      {/* Step Details */}
      {showSteps && progress.completedSteps && progress.completedSteps.length > 0 && (
        <div className="space-y-2 mb-4">
          {progress.completedSteps.map((step, index) => (
            <div key={index} className="flex items-center gap-2 text-xs">
              <CheckCircle className="w-3 h-3 text-green-500 flex-shrink-0" />
              <span className="text-[var(--copilot-kit-muted-color)]">{step.name}</span>
              <span className="text-[var(--copilot-kit-muted-color)] ml-auto">
                {step.durationMs}ms
              </span>
            </div>
          ))}
          {progress.currentStep && (
            <div className="flex items-center gap-2 text-xs">
              <Loader2 className="w-3 h-3 text-blue-500 flex-shrink-0 animate-spin" />
              <span className="text-[var(--copilot-kit-secondary-contrast-color)] font-medium">
                {progress.currentStep.name}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Error Display */}
      {progress.error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 mb-4">
          <div className="flex items-start gap-2">
            <XCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-red-400">{progress.error.message}</p>
              {progress.error.code && (
                <p className="text-xs text-red-400/70 mt-1">Error code: {progress.error.code}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      {(onRetry || onCancel) && (
        <div className="flex gap-2 justify-end">
          {onCancel && progress.status === 'running' && (
            <button
              onClick={onCancel}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[var(--copilot-kit-separator-color)]',
                'text-[var(--copilot-kit-secondary-contrast-color)]',
                'hover:bg-[var(--copilot-kit-separator-color)]/80',
                'transition-colors'
              )}
            >
              Cancel
            </button>
          )}
          {onRetry && progress.status === 'failed' && progress.error?.retryable && (
            <button
              onClick={onRetry}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[var(--copilot-kit-primary-color)]',
                'text-white',
                'hover:bg-[var(--copilot-kit-primary-color)]/80',
                'transition-colors'
              )}
            >
              Retry
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * WorkflowProgressInline - Minimal inline progress indicator.
 * Use in message bubbles or tight spaces.
 */
export function WorkflowProgressInline({
  progress,
  className,
}: {
  progress: WorkflowProgress;
  className?: string;
}) {
  const config = statusConfig[progress.status];
  const StatusIcon = config.icon;
  const isAnimating = progress.status === 'running';

  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <StatusIcon className={cn('w-3.5 h-3.5', config.color, isAnimating && 'animate-spin')} />
      <span className="text-xs text-[var(--copilot-kit-muted-color)]">
        {progress.message} ({progress.percent}%)
      </span>
    </span>
  );
}
