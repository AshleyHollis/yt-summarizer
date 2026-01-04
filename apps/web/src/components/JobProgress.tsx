'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { jobApi, VideoJobsProgress, JobType, JobStatus } from '@/services/api';

/**
 * Props for JobProgress
 */
export interface JobProgressProps {
  /** Video ID to track progress for */
  videoId: string;
  /** Polling interval in milliseconds (default: 3000) */
  pollingInterval?: number;
  /** Callback when processing completes */
  onComplete?: () => void;
  /** Callback when processing fails */
  onFailed?: (failedStage: JobType) => void;
  /** Custom class name */
  className?: string;
}

/**
 * Job stage display names
 */
const STAGE_LABELS: Record<JobType, string> = {
  transcribe: 'Extracting Transcript',
  summarize: 'Generating Summary',
  embed: 'Creating Embeddings',
  build_relationships: 'Finding Related Videos',
};

/**
 * Stage icons (using simple SVG)
 */
const StageIcon = ({ stage, status }: { stage: JobType; status: JobStatus }) => {
  const baseClass = 'w-6 h-6';

  // Completed checkmark
  if (status === 'completed') {
    return (
      <svg className={`${baseClass} text-green-500`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
      </svg>
    );
  }

  // Failed X
  if (status === 'failed') {
    return (
      <svg className={`${baseClass} text-red-500`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
      </svg>
    );
  }

  // Running spinner - blue for processing (semantic color)
  if (status === 'running') {
    return (
      <svg className={`${baseClass} text-blue-500 animate-spin`} fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
        />
      </svg>
    );
  }

  // Pending/queued circle
  return (
    <svg className={`${baseClass} text-gray-300 dark:text-gray-600`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <circle cx="12" cy="12" r="10" strokeWidth={2} />
    </svg>
  );
};

/**
 * Progress bar component
 */
const ProgressBar = ({ progress, hasError }: { progress: number; hasError: boolean }) => {
  return (
    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${
          hasError ? 'bg-red-500' : 'bg-blue-500'
        }`}
        style={{ width: `${progress}%` }}
        role="progressbar"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  );
};

/**
 * Component for displaying video processing job progress with polling
 */
export function JobProgress({
  videoId,
  pollingInterval = 3000,
  onComplete,
  onFailed,
  className = '',
}: JobProgressProps) {
  const [progress, setProgress] = useState<VideoJobsProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(true);

  /**
   * Fetch progress from API
   */
  const fetchProgress = useCallback(async () => {
    try {
      const data = await jobApi.getVideoProgress(videoId);
      setProgress(data);
      setError(null);

      // Check completion status from the overall_status field
      if (data.overall_status === 'completed') {
        setIsPolling(false);
        onComplete?.();
      } else if (data.overall_status === 'failed') {
        setIsPolling(false);
        // Find the failed job type
        const failedJob = data.jobs?.find(j => j.status === 'failed');
        if (failedJob) {
          onFailed?.(failedJob.job_type);
        }
      }
    } catch (err) {
      setError('Failed to fetch progress. Retrying...');
      console.error('Progress fetch error:', err);
    }
  }, [videoId, onComplete, onFailed]);

  /**
   * Set up polling
   */
  useEffect(() => {
    // Initial fetch
    fetchProgress();

    // Set up polling interval
    if (!isPolling) return;

    const intervalId = setInterval(fetchProgress, pollingInterval);

    return () => {
      clearInterval(intervalId);
    };
  }, [fetchProgress, pollingInterval, isPolling]);

  // Loading state
  if (!progress && !error) {
    return (
      <div className={`animate-pulse ${className}`}>
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded mb-4" />
        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded mb-6" />
        <div className="space-y-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
          ))}
        </div>
      </div>
    );
  }

  // Compute derived state
  const isComplete = progress?.overall_status === 'completed';
  const hasFailed = progress?.overall_status === 'failed';

  return (
    <div className={className}>
      {/* Header with overall progress */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Processing Progress
          </h3>
          <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
            {progress?.overall_progress ?? 0}%
          </span>
        </div>
        <ProgressBar
          progress={progress?.overall_progress ?? 0}
          hasError={hasFailed}
        />
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800">
          <p className="text-sm text-yellow-700 dark:text-yellow-300">{error}</p>
        </div>
      )}

      {/* Stage list */}
      <div className="space-y-3">
        {(progress?.jobs ?? []).map((job) => (
          <div
            key={job.job_id}
            className={`
              flex items-center gap-4 p-3 rounded-lg border
              ${job.status === 'running' ? 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20' : ''}
              ${job.status === 'completed' ? 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20' : ''}
              ${job.status === 'failed' ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' : ''}
              ${job.status === 'pending' ? 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800' : ''}
            `}
          >
            <StageIcon stage={job.job_type} status={job.status} />
            <div className="flex-1">
              <p
                className={`font-medium ${
                  job.status === 'running' ? 'text-blue-700 dark:text-blue-300' : ''
                } ${
                  job.status === 'completed' ? 'text-green-700 dark:text-green-300' : ''
                } ${
                  job.status === 'failed' ? 'text-red-700 dark:text-red-300' : ''
                } ${
                  job.status === 'pending' ? 'text-gray-500 dark:text-gray-400' : ''
                }`}
              >
                {STAGE_LABELS[job.job_type]}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                {job.status === 'running' ? 'In progress...' : job.status}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Completion message */}
      {isComplete && (
        <div className="mt-6 p-4 rounded-lg bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800">
          <div className="flex items-center gap-3">
            <svg
              className="h-6 w-6 text-green-500"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div>
              <p className="font-medium text-green-800 dark:text-green-200">
                Processing Complete!
              </p>
              <p className="text-sm text-green-700 dark:text-green-300">
                Transcript and summary are ready to view.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Failure message */}
      {hasFailed && (
        <div className="mt-6 p-4 rounded-lg bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800">
          <div className="flex items-start gap-3">
            <svg
              className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div>
              <p className="font-medium text-red-800 dark:text-red-200">
                Processing Failed
              </p>
              {(() => {
                const failedJob = progress?.jobs?.find(j => j.status === 'failed');
                return (
                  <>
                    <p className="text-sm text-red-700 dark:text-red-300">
                      Failed at: {failedJob ? STAGE_LABELS[failedJob.job_type] : 'Unknown stage'}
                    </p>
                    {failedJob?.error_message && (
                      <p className="text-sm text-red-600 dark:text-red-400 mt-2">
                        {failedJob.error_message}
                      </p>
                    )}
                  </>
                );
              })()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default JobProgress;
