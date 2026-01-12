'use client';

import { useEffect, useState, useRef } from 'react';
import { BatchDetailResponse, batchApi, BatchStatus, BatchItemStatus } from '@/services/api';

/**
 * Props for BatchProgress component
 */
export interface BatchProgressProps {
  /** Batch ID to track */
  batchId: string;
  /** Polling interval in ms for fallback (default 5000) */
  pollInterval?: number;
  /** Callback when batch completes */
  onComplete?: (batch: BatchDetailResponse) => void;
  /** Custom class name */
  className?: string;
}

/**
 * Get status color
 */
function getStatusColor(status: BatchStatus | BatchItemStatus): string {
  switch (status) {
    case 'pending':
      return 'text-gray-500 dark:text-gray-400';
    case 'running':
      return 'text-red-600 dark:text-red-400';
    case 'completed':
    case 'succeeded':
      return 'text-green-600 dark:text-green-400';
    case 'failed':
      return 'text-red-600 dark:text-red-400';
    default:
      return 'text-gray-500';
  }
}

/**
 * Get status icon
 */
function getStatusIcon(status: BatchItemStatus): string {
  switch (status) {
    case 'pending':
      return '○';
    case 'running':
      return '◐';
    case 'succeeded':
      return '●';
    case 'failed':
      return '✕';
    default:
      return '○';
  }
}

/**
 * Component to display batch ingestion progress
 */
export function BatchProgress({
  batchId,
  pollInterval = 5000,
  onComplete,
  className = '',
}: BatchProgressProps) {
  const [batch, setBatch] = useState<BatchDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [retryingItemId, setRetryingItemId] = useState<string | null>(null);
  const [useSSE, setUseSSE] = useState(true);
  const onCompleteRef = useRef(onComplete);

  // Keep onComplete ref updated
  useEffect(() => {
    onCompleteRef.current = onComplete;
  }, [onComplete]);

  useEffect(() => {
    let cleanup: (() => void) | null = null;
    let timeoutId: NodeJS.Timeout | null = null;
    let sseTimeoutId: NodeJS.Timeout | null = null;

    // Handle batch update
    const handleUpdate = (data: BatchDetailResponse) => {
      // Clear SSE timeout since we received data
      if (sseTimeoutId) {
        clearTimeout(sseTimeoutId);
        sseTimeoutId = null;
      }

      setBatch(data);
      setError(null);
      setIsLoading(false);

      // Check if complete
      const isComplete =
        data.status === 'completed' ||
        (data.succeeded_count + data.failed_count === data.total_count &&
          data.pending_count === 0 &&
          data.running_count === 0);

      if (isComplete) {
        onCompleteRef.current?.(data);
      }
    };

    // Handle error - fallback to polling
    const handleError = (err: Error) => {
      console.error('SSE error, falling back to polling:', err);
      if (sseTimeoutId) {
        clearTimeout(sseTimeoutId);
        sseTimeoutId = null;
      }
      setUseSSE(false);
    };

    // Handle completion
    const handleComplete = (data: BatchDetailResponse) => {
      if (sseTimeoutId) {
        clearTimeout(sseTimeoutId);
        sseTimeoutId = null;
      }
      setBatch(data);
      setError(null);
      setIsLoading(false);
      onCompleteRef.current?.(data);
    };

    // Use SSE for real-time updates
    if (useSSE && typeof window !== 'undefined' && typeof EventSource !== 'undefined') {
      // Set a timeout to fall back to polling if SSE doesn't connect within 5 seconds
      sseTimeoutId = setTimeout(() => {
        console.warn('SSE timeout, falling back to polling');
        cleanup?.();
        setUseSSE(false);
      }, 5000);
      cleanup = batchApi.streamProgress(
        batchId,
        handleUpdate,
        handleComplete,
        handleError
      );
    } else {
      // Fallback to polling
      let cancelled = false;

      const fetchBatch = async () => {
        try {
          const data = await batchApi.getById(batchId);
          if (!cancelled) {
            handleUpdate(data);

            // Check if complete
            const isComplete =
              data.status === 'completed' ||
              (data.succeeded_count + data.failed_count === data.total_count &&
                data.pending_count === 0 &&
                data.running_count === 0);

            if (!isComplete) {
              // Continue polling
              timeoutId = setTimeout(fetchBatch, pollInterval);
            }
          }
        } catch (err) {
          if (!cancelled) {
            setError('Failed to fetch batch status');
            setIsLoading(false);
            // Retry after delay
            timeoutId = setTimeout(fetchBatch, pollInterval * 2);
          }
        }
      };

      fetchBatch();

      cleanup = () => {
        cancelled = true;
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
      };
    }

    return () => {
      cleanup?.();
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      if (sseTimeoutId) {
        clearTimeout(sseTimeoutId);
      }
    };
  }, [batchId, pollInterval, useSSE]);

  /**
   * Handle retry failed items
   */
  const handleRetry = async () => {
    try {
      await batchApi.retryFailed(batchId);
      // Refresh batch data
      const data = await batchApi.getById(batchId);
      setBatch(data);
    } catch (err) {
      console.error('Retry failed:', err);
    }
  };

  /**
   * Handle retry a single failed item
   */
  const handleRetryItem = async (videoId: string) => {
    setRetryingItemId(videoId);
    try {
      await batchApi.retryItem(batchId, videoId);
      // Refresh batch data
      const data = await batchApi.getById(batchId);
      setBatch(data);
    } catch (err) {
      console.error('Retry item failed:', err);
    } finally {
      setRetryingItemId(null);
    }
  };

  if (isLoading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <svg
          className="animate-spin h-8 w-8 text-red-600"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      </div>
    );
  }

  if (error || !batch) {
    return (
      <div className={`text-center p-4 ${className}`}>
        <p className="text-red-600 dark:text-red-400">{error || 'Failed to load batch'}</p>
      </div>
    );
  }

  const progressPercent =
    batch.total_count > 0
      ? Math.round(((batch.succeeded_count + batch.failed_count) / batch.total_count) * 100)
      : 0;

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {batch.name || 'Batch Ingestion'}
          </h3>
          {batch.channel_name && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Channel: {batch.channel_name}
            </p>
          )}
        </div>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(batch.status)}`}>
          {batch.status.charAt(0).toUpperCase() + batch.status.slice(1)}
        </span>
      </div>

      {/* Progress bar */}
      <div>
        <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
          <span>{progressPercent}% complete</span>
          <span>
            {batch.succeeded_count + batch.failed_count} / {batch.total_count} videos
          </span>
        </div>
        <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <div className="h-full flex">
            <div
              className="bg-green-500 transition-all duration-300"
              style={{
                width: `${(batch.succeeded_count / batch.total_count) * 100}%`,
              }}
            />
            <div
              className="bg-red-500 transition-all duration-300"
              style={{
                width: `${(batch.failed_count / batch.total_count) * 100}%`,
              }}
            />
            <div
              className="bg-blue-500 animate-pulse transition-all duration-300"
              style={{
                width: `${(batch.running_count / batch.total_count) * 100}%`,
              }}
            />
          </div>
        </div>
      </div>

      {/* Status counts */}
      <div className="grid grid-cols-4 gap-2 text-center">
        <div className="bg-gray-50 dark:bg-gray-800 p-2 rounded">
          <div className="text-xl font-bold text-gray-600 dark:text-gray-400">
            {batch.pending_count}
          </div>
          <div className="text-xs text-gray-500">Pending</div>
        </div>
        <div className="bg-blue-50 dark:bg-blue-900/30 p-2 rounded">
          <div className="text-xl font-bold text-blue-600 dark:text-blue-400">
            {batch.running_count}
          </div>
          <div className="text-xs text-blue-500">Running</div>
        </div>
        <div className="bg-green-50 dark:bg-green-900/30 p-2 rounded">
          <div className="text-xl font-bold text-green-600 dark:text-green-400">
            {batch.succeeded_count}
          </div>
          <div className="text-xs text-green-500">Succeeded</div>
        </div>
        <div className="bg-red-50 dark:bg-red-900/30 p-2 rounded">
          <div className="text-xl font-bold text-red-600 dark:text-red-400">
            {batch.failed_count}
          </div>
          <div className="text-xs text-red-500">Failed</div>
        </div>
      </div>

      {/* Retry button for failed items */}
      {batch.failed_count > 0 && batch.running_count === 0 && batch.pending_count === 0 && (
        <button
          onClick={handleRetry}
          className="w-full py-2 px-4 bg-orange-100 text-orange-700 rounded-lg hover:bg-orange-200 transition-colors dark:bg-orange-900/30 dark:text-orange-400 dark:hover:bg-orange-900/50"
        >
          Retry {batch.failed_count} Failed Video{batch.failed_count !== 1 ? 's' : ''}
        </button>
      )}

      {/* Items list */}
      <div className="max-h-64 overflow-y-auto space-y-1">
        {batch.items.map((item) => (
          <div
            key={item.id}
            className="flex items-center gap-2 py-1.5 px-2 rounded bg-gray-50 dark:bg-gray-800"
          >
            <span className={`text-sm ${getStatusColor(item.status)}`}>
              {getStatusIcon(item.status)}
            </span>
            <span className="flex-1 text-sm text-gray-700 dark:text-gray-300 truncate">
              {item.title || item.youtube_video_id}
            </span>
            {item.status === 'running' && (
              <svg
                className="animate-spin h-4 w-4 text-blue-500"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                />
              </svg>
            )}
            {item.error_message && (
              <span
                className="text-xs text-red-500 truncate max-w-32"
                title={item.error_message}
              >
                {item.error_message}
              </span>
            )}
            {item.status === 'failed' && (
              <button
                onClick={() => handleRetryItem(item.youtube_video_id)}
                disabled={retryingItemId === item.youtube_video_id}
                className="flex-shrink-0 px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded hover:bg-orange-200 transition-colors disabled:opacity-50 dark:bg-orange-900/30 dark:text-orange-400 dark:hover:bg-orange-900/50"
                title="Retry this video"
              >
                {retryingItemId === item.youtube_video_id ? (
                  <svg
                    className="animate-spin h-3 w-3"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                ) : (
                  'Retry'
                )}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
