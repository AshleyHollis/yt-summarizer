/**
 * Warming Up Indicator - shows a banner when the database is waking up.
 * Used for serverless DB wake-up handling (FR-020).
 */

'use client';

import React from 'react';

export interface WarmingUpIndicatorProps {
  /** Current health status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Optional custom message */
  message?: string;
  /** Whether to show the indicator (defaults to showing when degraded) */
  show?: boolean;
}

/**
 * Banner component that displays when the API is in a degraded state.
 * Typically shown during serverless database cold start.
 */
export function WarmingUpIndicator({
  status,
  message,
  show,
}: WarmingUpIndicatorProps): React.ReactElement | null {
  // Determine if we should show the banner
  const shouldShow = show ?? status === 'degraded';

  if (!shouldShow) {
    return null;
  }

  // Select message and styling based on status
  let displayMessage = message;
  let bgColor = 'bg-yellow-500';
  let textColor = 'text-yellow-900';
  let Icon = WarmingIcon;

  if (status === 'degraded') {
    displayMessage = message || 'Warming up... The database is starting. This may take a moment.';
    bgColor = 'bg-yellow-100 dark:bg-yellow-900/30';
    textColor = 'text-yellow-800 dark:text-yellow-200';
  } else if (status === 'unhealthy') {
    displayMessage = message || 'Service unavailable. We\'re working to restore connectivity.';
    bgColor = 'bg-red-100 dark:bg-red-900/30';
    textColor = 'text-red-800 dark:text-red-200';
    Icon = ErrorIcon;
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className={`${bgColor} ${textColor} px-4 py-3 flex items-center justify-center gap-2 text-sm font-medium`}
      data-testid="warming-up-indicator"
    >
      <Icon className="h-5 w-5 animate-pulse" />
      <span>{displayMessage}</span>
    </div>
  );
}

function WarmingIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
      />
    </svg>
  );
}

function ErrorIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
      />
    </svg>
  );
}

export default WarmingUpIndicator;
