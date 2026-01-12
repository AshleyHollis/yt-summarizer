/**
 * Global Error Boundary for the application.
 * Handles uncaught errors and displays user-friendly error messages.
 */

'use client';

import { useEffect, useState } from 'react';

interface ErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function Error({ error, reset }: ErrorProps) {
  const [errorDetails, setErrorDetails] = useState<string | null>(null);
  const [isOnline, setIsOnline] = useState(true);
  const [correlationId, setCorrelationId] = useState<string | null>(null);

  useEffect(() => {
    // Check online status
    setIsOnline(navigator.onLine);

    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Log the error
    console.error('Application error:', error);

    // Extract correlation ID if available
    if (error.message.includes('correlation_id')) {
      try {
        const match = error.message.match(/correlation_id[:\s]+([a-f0-9-]+)/i);
        if (match) {
          setCorrelationId(match[1]);
        }
      } catch {
        // Ignore parsing errors
      }
    }

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [error]);

  // Determine error type and message
  const getErrorContent = () => {
    // Check for network/offline issues
    if (!isOnline) {
      return {
        title: 'You appear to be offline',
        message: 'Check your internet connection and try again.',
        icon: <WifiOffIcon className="h-12 w-12 text-gray-400" />,
      };
    }

    // Check for specific HTTP status codes in error message
    const errorMessage = error.message.toLowerCase();

    if (errorMessage.includes('503') || errorMessage.includes('service unavailable')) {
      return {
        title: 'Database is waking up',
        message: 'The database is starting up. This usually takes 30-60 seconds. Please wait...',
        icon: <DatabaseIcon className="h-12 w-12 text-yellow-500 animate-pulse" />,
      };
    }

    if (errorMessage.includes('502') || errorMessage.includes('bad gateway')) {
      return {
        title: 'Service temporarily unavailable',
        message: 'The server is temporarily unavailable. Please try again in a moment.',
        icon: <ServerIcon className="h-12 w-12 text-orange-500" />,
      };
    }

    if (errorMessage.includes('cannot connect') || errorMessage.includes('network')) {
      return {
        title: 'Cannot connect to server',
        message: 'Unable to reach the server. Please check if the service is running.',
        icon: <ServerIcon className="h-12 w-12 text-red-500" />,
      };
    }

    // Default error (also used for 500/internal server errors)
    const defaultError = {
      title: 'Something went wrong',
      message: 'An unexpected error occurred. Please try again.',
      icon: <ExclamationIcon className="h-12 w-12 text-red-500" />,
    };

    if (errorMessage.includes('500') || errorMessage.includes('internal server error')) {
      return defaultError;
    }

    return defaultError;
  };

  const { title, message, icon } = getErrorContent();

  const handleCopyError = () => {
    const details = [
      `Error: ${error.message}`,
      `Digest: ${error.digest || 'N/A'}`,
      `Correlation ID: ${correlationId || 'N/A'}`,
      `Timestamp: ${new Date().toISOString()}`,
      `URL: ${typeof window !== 'undefined' ? window.location.href : 'N/A'}`,
    ].join('\n');

    navigator.clipboard.writeText(details).then(() => {
      setErrorDetails('Copied to clipboard!');
      setTimeout(() => setErrorDetails(null), 2000);
    });
  };

  return (
    <div className="min-h-[50vh] flex items-center justify-center p-8">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 text-center">
        <div className="flex justify-center mb-4">{icon}</div>

        <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
          {title}
        </h1>

        <p className="text-gray-600 dark:text-gray-400 mb-6">
          {message}
        </p>

        <div className="flex flex-col gap-3">
          <button
            onClick={reset}
            className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
          >
            Try Again
          </button>

          <button
            onClick={handleCopyError}
            className="w-full px-4 py-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md transition-colors text-sm"
          >
            {errorDetails || 'Copy Error Details'}
          </button>
        </div>

        {correlationId && (
          <p className="mt-4 text-xs text-gray-500 dark:text-gray-500">
            Reference: {correlationId}
          </p>
        )}
      </div>
    </div>
  );
}

// Icon components
function WifiOffIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3m8.293 8.293l1.414 1.414" />
    </svg>
  );
}

function DatabaseIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
    </svg>
  );
}

function ServerIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  );
}

function ExclamationIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  );
}
