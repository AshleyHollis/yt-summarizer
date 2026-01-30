'use client';

import { useState, useEffect, useCallback } from 'react';
import { jobApi, VideoJobsProgress, JobType, JobStatus, JobStage, ETAInfo } from '@/services/api';
import { formatTimeShort } from '@/utils/formatDate';

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
const StageIcon = ({ status }: { stage: JobType; status: JobStatus; jobStage?: JobStage }) => {
  const baseClass = 'w-6 h-6';

  // Completed checkmark
  if (status === 'succeeded') {
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

  // Rate limited - clock/wait icon in orange
  if (jobStage === 'rate_limited') {
    return (
      <svg className={`${baseClass} text-orange-500`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
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
 * Component to show time until a future date
 */
const TimeUntil = ({ date }: { date: string }) => {
  const [timeLeft, setTimeLeft] = useState<string>('');

  useEffect(() => {
    const calculateTimeLeft = () => {
      // Ensure UTC parsing - server sends UTC times without 'Z' suffix
      const dateStr = date.endsWith('Z') ? date : date + 'Z';
      const targetDate = new Date(dateStr);
      const now = new Date();
      const diffMs = targetDate.getTime() - now.getTime();

      if (diffMs <= 0) {
        return 'any moment now';
      }

      const diffSeconds = Math.floor(diffMs / 1000);
      const minutes = Math.floor(diffSeconds / 60);
      const seconds = diffSeconds % 60;

      if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
      }
      return `${seconds}s`;
    };

    setTimeLeft(calculateTimeLeft());
    const interval = setInterval(() => {
      setTimeLeft(calculateTimeLeft());
    }, 1000);

    return () => clearInterval(interval);
  }, [date]);

  return <span className="font-mono">{timeLeft}</span>;
};

/**
 * Format seconds into human-readable duration
 */
const formatDuration = (seconds: number): string => {
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  if (minutes < 60) {
    return remainingSeconds > 0 ? `${minutes}m ${remainingSeconds}s` : `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
};

/**
 * ETA display component
 * Uses server's processing_started_at and estimated_total_seconds to calculate
 * remaining time, avoiding timer resets on refresh/polling
 */
const ETADisplay = ({ eta, currentStageName }: { eta: ETAInfo; currentStageName: string | null }) => {
  // Calculate target end time from server data
  const calculateTargetEndTime = useCallback(() => {
    if (eta.processing_started_at) {
      const startedAt = new Date(
        eta.processing_started_at.endsWith('Z')
          ? eta.processing_started_at
          : eta.processing_started_at + 'Z'
      );
      return startedAt.getTime() + eta.estimated_total_seconds * 1000;
    }
    return Date.now() + eta.estimated_seconds_remaining * 1000;
  }, [eta.processing_started_at, eta.estimated_total_seconds, eta.estimated_seconds_remaining]);

  // Initialize display seconds
  const [displaySeconds, setDisplaySeconds] = useState(() => {
    const targetTime = calculateTargetEndTime();
    return Math.max(0, Math.floor((targetTime - Date.now()) / 1000));
  });

  // Store the target end time (only update when processing_started_at changes)
  const [targetEndTime, setTargetEndTime] = useState(calculateTargetEndTime);

  // Update target end time only when processing_started_at changes (new job started)
  useEffect(() => {
    if (eta.processing_started_at) {
      const newTarget = calculateTargetEndTime();
      setTargetEndTime(newTarget);
    }
  }, [eta.processing_started_at, calculateTargetEndTime]);

  // Countdown effect - calculates based on target end time, not server value
  useEffect(() => {
    const updateDisplay = () => {
      const remaining = Math.floor((targetEndTime - Date.now()) / 1000);
      setDisplaySeconds(Math.max(0, remaining));
    };

    updateDisplay();
    const interval = setInterval(updateDisplay, 1000);

    return () => clearInterval(interval);
  }, [targetEndTime]);

  return (
    <div className="mb-6 p-4 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
      <div className="flex items-start gap-3">
        {/* Clock icon */}
        <svg
          className="w-6 h-6 text-blue-500 flex-shrink-0 mt-0.5"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <div className="flex-1">
          {/* Main ETA */}
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-2xl font-bold text-blue-700 dark:text-blue-300 font-mono">
              {formatDuration(displaySeconds)}
            </span>
            <span className="text-sm text-blue-600 dark:text-blue-400">
              estimated time remaining
            </span>
          </div>

          {/* Ready at time */}
          <p className="text-sm text-blue-600 dark:text-blue-400 mb-2">
            Ready at approximately <span className="font-mono font-medium">{formatTimeShort(eta.estimated_ready_at)}</span>
          </p>

          {/* Current stage */}
          {currentStageName && (
            <p className="text-sm text-blue-600 dark:text-blue-400 mb-2">
              Currently: <span className="font-medium">{currentStageName}</span>
            </p>
          )}

          {/* Queue info - only show when video is waiting (not yet started processing) */}
          {eta.videos_ahead > 0 && !eta.processing_started_at && (
            <div className="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
                />
              </svg>
              <span>
                Position <span className="font-mono font-medium">{eta.queue_position}</span> of{' '}
                <span className="font-mono font-medium">{eta.total_in_queue}</span> in queue
                {eta.videos_ahead > 0 && (
                  <span className="text-blue-500 dark:text-blue-400">
                    {' '}• ~{formatDuration(eta.queue_wait_seconds)} waiting for {eta.videos_ahead} video{eta.videos_ahead > 1 ? 's' : ''} ahead
                  </span>
                )}
              </span>
            </div>
          )}

          {/* Stages breakdown */}
          {eta.stages_remaining.length > 0 && (
            <div className="mt-3 pt-3 border-t border-blue-200 dark:border-blue-700">
              <p className="text-xs text-blue-500 dark:text-blue-400 mb-2">Remaining stages:</p>
              <div className="flex flex-wrap gap-2">
                {eta.stages_remaining.map((stage) => (
                  <span
                    key={stage.stage}
                    className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 dark:bg-blue-800/50 text-blue-700 dark:text-blue-300"
                  >
                    {stage.stage.replace('_', ' ')} • ~{formatDuration(stage.estimated_seconds)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
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
  const isProcessing = !isComplete && !hasFailed;

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

      {/* ETA display - only show when processing and ETA is available */}
      {isProcessing && progress?.eta && (
        <ETADisplay eta={progress.eta} currentStageName={progress.current_stage_name} />
      )}

      {/* Error banner */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800">
          <p className="text-sm text-yellow-700 dark:text-yellow-300">{error}</p>
        </div>
      )}

      {/* Stage list */}
      <div className="space-y-3">
        {(progress?.jobs ?? []).map((job) => {
          const isRateLimited = job.stage === 'rate_limited';
          return (
            <div
              key={job.job_id}
              className={`
                flex items-center gap-4 p-3 rounded-lg border
                ${isRateLimited ? 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20' : ''}
                ${job.status === 'running' && !isRateLimited ? 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20' : ''}
                ${job.status === 'succeeded' ? 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20' : ''}
                ${job.status === 'failed' ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' : ''}
                ${job.status === 'pending' ? 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800' : ''}
              `}
            >
              <StageIcon stage={job.job_type} status={job.status} jobStage={job.stage} />
              <div className="flex-1">
                <p
                  className={`font-medium ${
                    isRateLimited ? 'text-orange-700 dark:text-orange-300' : ''
                  } ${
                    job.status === 'running' && !isRateLimited ? 'text-blue-700 dark:text-blue-300' : ''
                  } ${
                    job.status === 'succeeded' ? 'text-green-700 dark:text-green-300' : ''
                  } ${
                    job.status === 'failed' ? 'text-red-700 dark:text-red-300' : ''
                  } ${
                    job.status === 'pending' ? 'text-gray-500 dark:text-gray-400' : ''
                  }`}
                >
                  {STAGE_LABELS[job.job_type]}
                </p>
                {isRateLimited ? (
                  <div className="text-sm text-orange-600 dark:text-orange-400">
                    <p>Rate limited by YouTube • Attempt #{job.retry_count || 1}</p>
                    {job.next_retry_at && (
                      <p className="text-xs">
                        Next retry: <TimeUntil date={job.next_retry_at} />
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                    {job.status === 'running' ? 'In progress...' : job.status}
                  </p>
                )}
              </div>
            </div>
          );
        })}
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
