/**
 * Error Boundary Component
 *
 * React Error Boundary to catch and display authentication errors gracefully.
 * Prevents the entire app from crashing when auth-related errors occur.
 *
 * @module ErrorBoundary
 *
 * Implementation: T066
 */

'use client';

import React, { Component, ReactNode, ErrorInfo } from 'react';

// ============================================================================
// Type Definitions
// ============================================================================

interface ErrorBoundaryProps {
  /** Child components to wrap with error boundary */
  children: ReactNode;

  /** Optional fallback UI to show when error occurs */
  fallback?: (error: Error, errorInfo: ErrorInfo) => ReactNode;

  /** Optional callback when error is caught */
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface ErrorBoundaryState {
  /** Whether an error has been caught */
  hasError: boolean;

  /** The caught error (if any) */
  error: Error | null;

  /** React error info with component stack */
  errorInfo: ErrorInfo | null;
}

// ============================================================================
// Error Boundary Component
// ============================================================================

/**
 * Error Boundary for React Component Errors
 *
 * Catches JavaScript errors anywhere in the child component tree and displays
 * a fallback UI instead of crashing the entire application.
 *
 * @remarks
 * Error boundaries catch errors during:
 * - Rendering
 * - Lifecycle methods
 * - Constructors of child components
 *
 * Error boundaries do NOT catch errors in:
 * - Event handlers (use try/catch instead)
 * - Asynchronous code (setTimeout, requestAnimationFrame, etc.)
 * - Server-side rendering
 * - Errors thrown in the error boundary itself
 *
 * @example
 * ```tsx
 * // Wrap authentication UI with error boundary
 * <ErrorBoundary>
 *   <AuthProvider>
 *     <App />
 *   </AuthProvider>
 * </ErrorBoundary>
 * ```
 *
 * @example
 * ```tsx
 * // Custom fallback UI and error reporting
 * <ErrorBoundary
 *   fallback={(error, errorInfo) => (
 *     <div>
 *       <h1>Authentication Error</h1>
 *       <p>{error.message}</p>
 *     </div>
 *   )}
 *   onError={(error, errorInfo) => {
 *     console.error('Auth error:', error, errorInfo);
 *     // Send to error tracking service (e.g., Sentry)
 *   }}
 * >
 *   <AuthProvider>
 *     <App />
 *   </AuthProvider>
 * </ErrorBoundary>
 * ```
 *
 * @see https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  /**
   * Static lifecycle method called when error is caught
   *
   * @param error - The error that was thrown
   * @returns New state to trigger re-render with error UI
   */
  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    // Update state so next render shows fallback UI
    return {
      hasError: true,
      error,
    };
  }

  /**
   * Lifecycle method called after error is caught
   *
   * @param error - The error that was thrown
   * @param errorInfo - React error info with component stack trace
   */
  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Update state with detailed error info
    this.setState({
      errorInfo,
    });

    // Log error to console
    console.error('ErrorBoundary caught an error:', error, errorInfo);

    // Call optional error callback
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }
  }

  /**
   * Reset error state to retry rendering
   */
  resetError = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render(): ReactNode {
    const { hasError, error, errorInfo } = this.state;
    const { children, fallback } = this.props;

    // If error occurred, show fallback UI
    if (hasError && error) {
      // Use custom fallback if provided
      if (fallback && errorInfo) {
        return fallback(error, errorInfo);
      }

      // Default fallback UI
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
          <div className="max-w-md w-full bg-white shadow-lg rounded-lg p-6">
            <div className="flex items-center justify-center w-12 h-12 mx-auto bg-red-100 rounded-full mb-4">
              <svg
                className="w-6 h-6 text-red-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>

            <h1 className="text-2xl font-bold text-gray-900 text-center mb-2">
              Something went wrong
            </h1>

            <p className="text-gray-600 text-center mb-6">
              An error occurred while loading the application. Please try again.
            </p>

            {/* Error details (only show in development) */}
            {process.env.NODE_ENV === 'development' && (
              <div className="mb-6 p-4 bg-gray-100 rounded-md overflow-auto">
                <p className="text-sm font-semibold text-gray-700 mb-2">Error Details:</p>
                <p className="text-xs text-red-600 font-mono break-words">
                  {error.toString()}
                </p>
                {errorInfo && (
                  <details className="mt-2">
                    <summary className="text-xs text-gray-600 cursor-pointer hover:text-gray-800">
                      Component Stack
                    </summary>
                    <pre className="text-xs text-gray-600 mt-2 whitespace-pre-wrap">
                      {errorInfo.componentStack}
                    </pre>
                  </details>
                )}
              </div>
            )}

            {/* Action buttons */}
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={this.resetError}
                className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.href = '/'}
                className="flex-1 bg-gray-200 text-gray-800 px-4 py-2 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-colors"
              >
                Go Home
              </button>
            </div>
          </div>
        </div>
      );
    }

    // No error, render children normally
    return children;
  }
}

/**
 * Default export for easier imports
 */
export default ErrorBoundary;
