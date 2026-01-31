'use client';

import { useState, useEffect, useCallback } from 'react';
import { jobApi, VideoProcessingHistory, StageHistoryItem } from '@/services/api';
import { formatDateTime, formatTime } from '@/utils/formatDate';
import { formatElapsedTime } from '@/utils/formatDuration';

/**
 * Props for ProcessingHistory component
 */
export interface ProcessingHistoryProps {
  /** Video ID to fetch history for */
  videoId: string;
  /** Custom class name */
  className?: string;
}

/**
 * Format variance with color and sign
 */
function formatVariance(variance: number | null, variancePercent: number | null): React.ReactNode {
  if (variance === null) return null;

  const isPositive = variance > 0;
  const isNegative = variance < 0;
  const sign = isPositive ? '+' : '';
  const colorClass = isPositive
    ? 'text-red-600 dark:text-red-400'
    : isNegative
      ? 'text-green-600 dark:text-green-400'
      : 'text-gray-500';

  return (
    <span className={colorClass}>
      {sign}{formatElapsedTime(Math.abs(variance))}
      {variancePercent !== null && (
        <span className="text-xs ml-1">({sign}{Math.round(variancePercent)}%)</span>
      )}
    </span>
  );
}

/**
 * Stage row component
 */
function StageRow({ stage, showWait }: { stage: StageHistoryItem; showWait: boolean }) {
  const statusIcon = stage.status === 'succeeded' ? '✓' : stage.status === 'failed' ? '✗' : '○';
  const statusColorClass =
    stage.status === 'succeeded'
      ? 'text-green-500'
      : stage.status === 'failed'
        ? 'text-red-500'
        : 'text-gray-400';

  // Note: estimated_seconds already includes enforced delay (baked into historical avg)
  // The delay is shown separately just for informational purposes
  const hasDelay = (stage.estimated_delay_seconds ?? 0) > 0;

  return (
    <tr className="border-b border-gray-100 dark:border-gray-700 last:border-b-0">
      <td className="py-3 pr-4">
        <div className="flex items-center gap-2">
          <span className={`text-lg ${statusColorClass}`}>{statusIcon}</span>
          <div>
            <span className="font-medium text-gray-900 dark:text-gray-100">
              {stage.stage_label}
            </span>
            {stage.retry_count > 0 && (
              <span className="ml-2 text-xs px-1.5 py-0.5 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300">
                {stage.retry_count} {stage.retry_count === 1 ? 'retry' : 'retries'}
              </span>
            )}
          </div>
        </div>
      </td>
      {showWait && (
        <td className="py-3 px-4 text-right font-mono text-sm text-gray-500 dark:text-gray-500">
          {stage.wait_seconds !== null && stage.wait_seconds > 0.5
            ? formatElapsedTime(stage.wait_seconds)
            : '-'}
        </td>
      )}
      <td className="py-3 px-4 text-right font-mono text-sm text-gray-600 dark:text-gray-400">
        <span>{formatElapsedTime(stage.estimated_seconds)}</span>
        {hasDelay && (
          <span className="block text-xs text-gray-400 dark:text-gray-500">
            (incl. ~{formatElapsedTime(stage.estimated_delay_seconds)} delay)
          </span>
        )}
      </td>
      <td className="py-3 px-4 text-right font-mono text-sm text-gray-900 dark:text-gray-100 font-medium">
        {formatElapsedTime(stage.actual_seconds)}
      </td>
      <td className="py-3 pl-4 text-right font-mono text-sm">
        {formatVariance(stage.variance_seconds, stage.variance_percent)}
      </td>
    </tr>
  );
}

/**
 * Percentile badge component
 */
function PercentileBadge({ percentile }: { percentile: number }) {
  let colorClass = 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
  let label = 'Average';

  if (percentile >= 75) {
    colorClass = 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
    label = 'Fast';
  } else if (percentile >= 60) {
    colorClass = 'bg-green-50 text-green-600 dark:bg-green-900/20 dark:text-green-400';
    label = 'Above Average';
  } else if (percentile <= 25) {
    colorClass = 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
    label = 'Slow';
  } else if (percentile <= 40) {
    colorClass = 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
    label = 'Below Average';
  }

  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {label} ({percentile}th percentile)
    </span>
  );
}

/**
 * Processing History component
 * Shows detailed timing breakdown of video processing stages
 */
export function ProcessingHistory({ videoId, className = '' }: ProcessingHistoryProps) {
  const [history, setHistory] = useState<VideoProcessingHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await jobApi.getVideoHistory(videoId);
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch processing history:', err);
      setError('Failed to load processing history');
    } finally {
      setLoading(false);
    }
  }, [videoId]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Loading state
  if (loading) {
    return (
      <div className={`animate-pulse ${className}`}>
        <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-48 mb-4" />
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-12 bg-gray-200 dark:bg-gray-700 rounded" />
          ))}
        </div>
      </div>
    );
  }

  // Error state
  if (error || !history) {
    return (
      <div className={`text-center py-8 ${className}`}>
        <p className="text-gray-500 dark:text-gray-400">{error || 'No history available'}</p>
      </div>
    );
  }

  // No stages processed yet
  if (history.stages.length === 0) {
    return (
      <div className={`text-center py-8 ${className}`}>
        <p className="text-gray-500 dark:text-gray-400">Processing has not started yet</p>
      </div>
    );
  }

  // Calculate display values
  // Note: estimated_seconds already INCLUDES enforced delays (they're baked into
  // historical averages since job duration includes sleep time)
  // Track if enforced delays exist (used for potential future UI indicator)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _hasEnforcedDelay = (history.total_estimated_delay_seconds ?? 0) > 0;
  const hasQueueWait = (history.total_wait_seconds ?? 0) > 0 || (history.total_estimated_wait_seconds ?? 0) > 0;
  const queueWaitVariance = (history.total_wait_seconds ?? 0) - (history.total_estimated_wait_seconds ?? 0);

  return (
    <div className={className}>
      {/* Summary Stats */}
      <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Total Elapsed Time */}
        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Total Elapsed</p>
          <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
            {formatElapsedTime(history.total_elapsed_seconds)}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {formatElapsedTime(history.total_wait_seconds)} queue + {formatElapsedTime(history.total_actual_seconds)} processing
          </p>
        </div>

        {/* Queue Wait Estimate vs Actual */}
        {hasQueueWait && (
          <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Queue Wait</p>
            <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
              {formatElapsedTime(history.total_wait_seconds)}
            </p>
            {history.total_estimated_wait_seconds !== null && history.total_estimated_wait_seconds > 0 && (
              <>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Est. {formatElapsedTime(history.total_estimated_wait_seconds)}
                </p>
                <p className="text-xs mt-0.5">
                  {formatVariance(queueWaitVariance, null)}
                </p>
              </>
            )}
          </div>
        )}

        {/* Expected Processing Time (estimate already includes enforced delay) */}
        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Processing</p>
          <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
            {formatElapsedTime(history.total_actual_seconds)}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Est. {formatElapsedTime(history.total_estimated_seconds)}
          </p>
          {history.total_variance_seconds !== null && (
            <p className="text-xs mt-0.5">
              {formatVariance(history.total_variance_seconds, null)}
            </p>
          )}
        </div>

        {/* Stages & Retries */}
        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Stages</p>
          <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
            {history.stages_completed}/{history.stages.length}
            {history.stages_failed > 0 && (
              <span className="text-red-500 text-sm ml-1">({history.stages_failed} failed)</span>
            )}
          </p>
          {history.total_retries > 0 && (
            <p className="text-xs text-orange-600 dark:text-orange-400 mt-1">
              {history.total_retries} {history.total_retries === 1 ? 'retry' : 'retries'}
            </p>
          )}
        </div>

        {/* Speed Comparison */}
        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Speed</p>
          {history.percentile !== null ? (
            <PercentileBadge percentile={history.percentile} />
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">-</p>
          )}
        </div>
      </div>

      {/* Stage Breakdown Table */}
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        {/* Determine if we should show wait column */}
        {(() => {
          const showWait = (history.total_wait_seconds ?? 0) > 1; // Only show if wait > 1 second
          return (
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50 dark:bg-gray-800/80 text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <th className="py-2 px-4 text-left font-medium">Stage</th>
                  {showWait && <th className="py-2 px-4 text-right font-medium">Wait</th>}
                  <th className="py-2 px-4 text-right font-medium">Est.</th>
                  <th className="py-2 px-4 text-right font-medium">Processing</th>
                  <th className="py-2 px-4 text-right font-medium">Variance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {history.stages.map((stage) => (
                  <StageRow key={stage.stage} stage={stage} showWait={showWait} />
                ))}
              </tbody>
              {/* Totals row */}
              <tfoot>
                <tr className="bg-gray-50 dark:bg-gray-800/50 font-medium">
                  <td className="py-3 px-4 text-gray-900 dark:text-gray-100">Total</td>
                  {showWait && (
                    <td className="py-3 px-4 text-right font-mono text-sm text-gray-500 dark:text-gray-500">
                      {formatElapsedTime(history.total_wait_seconds)}
                    </td>
                  )}
                  <td className="py-3 px-4 text-right font-mono text-sm text-gray-600 dark:text-gray-400">
                    {formatElapsedTime(history.total_estimated_seconds)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm text-gray-900 dark:text-gray-100">
                    {formatElapsedTime(history.total_actual_seconds)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm">
                    {formatVariance(history.total_variance_seconds, null)}
                  </td>
                </tr>
              </tfoot>
            </table>
          );
        })()}
      </div>

      {/* Video Duration Note */}
      {history.video_duration_seconds && (
        <p className="mt-4 text-xs text-gray-500 dark:text-gray-400">
          Video duration: {formatElapsedTime(history.video_duration_seconds)}
        </p>
      )}

      {/* Timestamps Section (Collapsible for troubleshooting) */}
      <details className="mt-4 text-xs">
        <summary className="cursor-pointer text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300">
          Show timestamps for troubleshooting
        </summary>
        <div className="mt-2 p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg space-y-2 font-mono">
          {/* Overall timestamps */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 pb-2 border-b border-gray-200 dark:border-gray-700">
            <span className="text-gray-500">Submitted:</span>
            <span className="text-gray-700 dark:text-gray-300">{formatDateTime(history.submitted_at)}</span>
            <span className="text-gray-500">First job started:</span>
            <span className="text-gray-700 dark:text-gray-300">{formatDateTime(history.first_job_started_at)}</span>
            <span className="text-gray-500">Last job completed:</span>
            <span className="text-gray-700 dark:text-gray-300">{formatDateTime(history.last_job_completed_at)}</span>
          </div>

          {/* Per-stage timestamps */}
          <div className="pt-1">
            <p className="text-gray-500 mb-2">Stage timestamps:</p>
            <table className="w-full text-left">
              <thead>
                <tr className="text-gray-500">
                  <th className="pr-2 font-normal">Stage</th>
                  <th className="px-2 font-normal">Queued</th>
                  <th className="px-2 font-normal">Started</th>
                  <th className="px-2 font-normal">Completed</th>
                </tr>
              </thead>
              <tbody className="text-gray-700 dark:text-gray-300">
                {history.stages.map((stage) => (
                  <tr key={stage.stage}>
                    <td className="pr-2 py-0.5">{stage.stage}</td>
                    <td className="px-2 py-0.5">{formatTime(stage.queued_at)}</td>
                    <td className="px-2 py-0.5">{formatTime(stage.started_at)}</td>
                    <td className="px-2 py-0.5">{formatTime(stage.completed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </details>
    </div>
  );
}

export default ProcessingHistory;
