/**
 * AuthGate Component
 *
 * Wraps content that requires authentication. Shows a login prompt
 * with context message when the user is not authenticated.
 *
 * Unlike RoleBasedComponent (which silently hides content), AuthGate
 * actively prompts the user to log in.
 */

'use client';

import React from 'react';
import { useAuth } from '@/hooks/useAuth';
import { LoginButton } from './LoginButton';

interface AuthGateProps {
  /** What action requires login (shown in the prompt) */
  action?: string;
  /** Content to show when authenticated */
  children: React.ReactNode;
}

/**
 * Shows children if authenticated, otherwise shows a login prompt.
 *
 * @example
 * ```tsx
 * <AuthGate action="submit videos">
 *   <SubmitVideoForm />
 * </AuthGate>
 * ```
 */
export function AuthGate({ action = 'use this feature', children }: AuthGateProps) {
  const { isLoading, isAuthenticated } = useAuth();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-400" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center p-8 space-y-6">
        <div className="text-center space-y-2">
          <svg
            className="w-12 h-12 mx-auto text-gray-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
            />
          </svg>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Sign in required
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 max-w-sm">
            You need to sign in to {action}. Your data is secure and we only use your
            account for quota tracking.
          </p>
        </div>
        <div className="w-full max-w-xs">
          <LoginButton />
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
