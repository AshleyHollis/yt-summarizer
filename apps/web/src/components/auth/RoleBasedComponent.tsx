/**
 * RoleBasedComponent - Conditionally render UI based on user role
 *
 * This component wraps content that should only be visible to users with specific roles.
 * It's useful for:
 * - Admin-only navigation items
 * - Role-specific dashboard sections
 * - Feature flags based on user permissions
 *
 * @example
 * ```tsx
 * <RoleBasedComponent requiredRole="admin">
 *   <AdminPanel />
 * </RoleBasedComponent>
 * ```
 *
 * @example With fallback
 * ```tsx
 * <RoleBasedComponent
 *   requiredRole="admin"
 *   fallback={<div>Admin access required</div>}
 * >
 *   <AdminSettings />
 * </RoleBasedComponent>
 * ```
 */

'use client';

import React from 'react';
import { useAuth } from '../../hooks/useAuth';

interface RoleBasedComponentProps {
  /**
   * The role required to view the children.
   * If undefined, only authentication is required (no specific role).
   */
  requiredRole?: string;

  /**
   * Fallback content to display when the user doesn't have the required role.
   * Defaults to null (nothing rendered).
   */
  fallback?: React.ReactNode;

  /**
   * Whether to show a loading indicator while auth state is being determined.
   * Defaults to false.
   */
  showLoading?: boolean;

  /**
   * The content to conditionally render based on the user's role.
   */
  children: React.ReactNode;
}

/**
 * RoleBasedComponent
 *
 * Renders children only if the user is authenticated and has the required role.
 *
 * Rendering logic:
 * 1. If loading and showLoading=true → Show loading indicator
 * 2. If not authenticated → Show fallback (or nothing)
 * 3. If no requiredRole specified → Show children (auth-only check)
 * 4. If user has requiredRole → Show children
 * 5. Otherwise → Show fallback (or nothing)
 */
export function RoleBasedComponent({
  requiredRole,
  fallback = null,
  showLoading = false,
  children,
}: RoleBasedComponentProps) {
  const { user, isLoading, isAuthenticated } = useAuth();

  // Show loading state if enabled
  if (isLoading && showLoading) {
    return (
      <div data-testid="role-loading" className="flex items-center justify-center p-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
        <span className="ml-2 text-gray-600">Loading...</span>
      </div>
    );
  }

  // Not authenticated - show fallback
  if (!isAuthenticated || !user) {
    return <>{fallback}</>;
  }

  // No role requirement - show children (auth-only protection)
  if (!requiredRole) {
    return <>{children}</>;
  }

  // Check if user has the required role
  const userRole = user['https://yt-summarizer.com/role'];
  const hasRequiredRole = userRole === requiredRole;

  if (hasRequiredRole) {
    return <>{children}</>;
  }

  // User doesn't have required role - show fallback
  return <>{fallback}</>;
}

/**
 * AdminOnly - Convenience wrapper for admin-only content
 *
 * @example
 * ```tsx
 * <AdminOnly>
 *   <AdminDashboard />
 * </AdminOnly>
 * ```
 */
export function AdminOnly({
  fallback,
  children,
}: {
  fallback?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <RoleBasedComponent requiredRole="admin" fallback={fallback}>
      {children}
    </RoleBasedComponent>
  );
}
