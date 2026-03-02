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
import { UsernamePasswordForm } from './UsernamePasswordForm';

interface AuthGateProps {
  /** What action requires login (shown in the prompt) */
  action?: string;
  /** Content to show when authenticated */
  children: React.ReactNode;
}

/**
 * Shows children if authenticated, otherwise shows a login prompt.
 * Includes social login (OAuth) and email/password form for consistency
 * with the /sign-in page.
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
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Sign in required</h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 max-w-sm">
            You need to sign in to {action}. Your data is secure and we only use your account for
            quota tracking.
          </p>
        </div>
        <div className="w-full max-w-sm">
          <LoginButton />

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-300 dark:border-gray-600"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-gray-100 dark:bg-[#0f0f0f] text-gray-500 dark:text-gray-400">
                Or continue with email
              </span>
            </div>
          </div>

          <UsernamePasswordForm />
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
