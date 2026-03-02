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
import { LoginCard } from './LoginCard';

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
      <div className="flex flex-col items-center justify-center p-8">
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">Sign in to {action}</p>
        <div className="max-w-md w-full">
          <LoginCard />
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
