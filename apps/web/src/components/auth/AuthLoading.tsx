/**
 * Auth Loading Component
 *
 * Loading spinner and skeleton UI for authentication state transitions.
 * Provides a smooth user experience while auth state is being determined.
 *
 * @module AuthLoading
 *
 * Implementation: T067
 */

'use client';

import React from 'react';

// ============================================================================
// Type Definitions
// ============================================================================

interface AuthLoadingProps {
  /** Loading message to display (optional) */
  message?: string;

  /** Size variant: small, medium, large */
  size?: 'small' | 'medium' | 'large';

  /** Whether to show full-screen overlay */
  fullScreen?: boolean;
}

// ============================================================================
// Loading Spinner Component
// ============================================================================

/**
 * Animated loading spinner
 *
 * @param size - Spinner size (small: 4, medium: 8, large: 12)
 */
function Spinner({ size = 'medium' }: { size?: 'small' | 'medium' | 'large' }) {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
  };

  return (
    <svg
      className={`animate-spin ${sizeClasses[size]} text-blue-600`}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

// ============================================================================
// Auth Loading Component
// ============================================================================

/**
 * Auth Loading Component
 *
 * Displays a loading spinner with optional message while authentication
 * state is being determined.
 *
 * @param props - Component props
 * @param props.message - Optional loading message
 * @param props.size - Size variant (default: 'medium')
 * @param props.fullScreen - Whether to show full-screen overlay (default: false)
 * @returns Loading UI component
 *
 * @remarks
 * Use this component when:
 * - Initial auth state is loading (on app mount)
 * - User is being redirected after login
 * - Session is being refreshed
 * - User is being logged out
 *
 * @example
 * ```tsx
 * // Basic usage in AuthContext
 * function AuthProvider({ children }) {
 *   const { isLoading } = useAuth();
 *
 *   if (isLoading) {
 *     return <AuthLoading message="Loading authentication..." />;
 *   }
 *
 *   return children;
 * }
 * ```
 *
 * @example
 * ```tsx
 * // Full-screen loading overlay
 * <AuthLoading
 *   message="Signing you in..."
 *   size="large"
 *   fullScreen
 * />
 * ```
 *
 * @example
 * ```tsx
 * // Small inline loading spinner
 * <AuthLoading size="small" />
 * ```
 */
export function AuthLoading({
  message = 'Loading...',
  size = 'medium',
  fullScreen = false,
}: AuthLoadingProps) {
  // Full-screen overlay variant
  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-white bg-opacity-90 flex items-center justify-center z-50">
        <div className="flex flex-col items-center gap-4">
          <Spinner size={size} />
          {message && <p className="text-gray-600 text-lg font-medium animate-pulse">{message}</p>}
        </div>
      </div>
    );
  }

  // Inline centered variant
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-8">
      <Spinner size={size} />
      {message && <p className="text-gray-600 text-sm animate-pulse">{message}</p>}
    </div>
  );
}

// ============================================================================
// Skeleton Loading Components
// ============================================================================

/**
 * Skeleton loading placeholder for user profile
 *
 * Shows a pulsing skeleton UI while user profile is loading.
 * Matches the structure of the UserProfile component.
 *
 * @example
 * ```tsx
 * function UserProfileContainer() {
 *   const { user, isLoading } = useAuth();
 *
 *   if (isLoading) {
 *     return <UserProfileSkeleton />;
 *   }
 *
 *   return <UserProfile user={user} />;
 * }
 * ```
 */
export function UserProfileSkeleton() {
  return (
    <div className="flex items-center gap-3 animate-pulse">
      {/* Avatar skeleton */}
      <div className="w-10 h-10 bg-gray-300 rounded-full" />

      <div className="flex flex-col gap-2">
        {/* Name skeleton */}
        <div className="h-4 w-24 bg-gray-300 rounded" />

        {/* Email skeleton */}
        <div className="h-3 w-32 bg-gray-200 rounded" />
      </div>
    </div>
  );
}

/**
 * Skeleton loading placeholder for navigation menu
 *
 * Shows pulsing skeleton UI for navigation items while auth state is loading.
 *
 * @example
 * ```tsx
 * function Navigation() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (isLoading) {
 *     return <NavigationSkeleton />;
 *   }
 *
 *   return <NavigationMenu />;
 * }
 * ```
 */
export function NavigationSkeleton() {
  return (
    <div className="flex items-center gap-4 animate-pulse">
      {/* Nav item 1 */}
      <div className="h-4 w-16 bg-gray-300 rounded" />

      {/* Nav item 2 */}
      <div className="h-4 w-20 bg-gray-300 rounded" />

      {/* Nav item 3 */}
      <div className="h-4 w-14 bg-gray-300 rounded" />

      {/* User menu */}
      <div className="w-8 h-8 bg-gray-300 rounded-full" />
    </div>
  );
}

/**
 * Skeleton loading placeholder for protected page content
 *
 * Shows pulsing skeleton UI for page content while auth is being verified.
 *
 * @example
 * ```tsx
 * function ProtectedPage() {
 *   const { isLoading, hasRole } = useAuth();
 *
 *   if (isLoading) {
 *     return <PageContentSkeleton />;
 *   }
 *
 *   if (!hasRole('admin')) {
 *     return <AccessDenied />;
 *   }
 *
 *   return <AdminDashboard />;
 * }
 * ```
 */
export function PageContentSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {/* Page title */}
      <div className="h-8 w-64 bg-gray-300 rounded" />

      {/* Subtitle */}
      <div className="h-4 w-96 bg-gray-200 rounded" />

      <div className="space-y-3 mt-8">
        {/* Content lines */}
        <div className="h-4 bg-gray-200 rounded w-full" />
        <div className="h-4 bg-gray-200 rounded w-5/6" />
        <div className="h-4 bg-gray-200 rounded w-4/6" />
        <div className="h-4 bg-gray-200 rounded w-full" />
        <div className="h-4 bg-gray-200 rounded w-3/6" />
      </div>
    </div>
  );
}

/**
 * Default export for easier imports
 */
export default AuthLoading;
