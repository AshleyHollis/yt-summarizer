/**
 * useAuth Hook
 *
 * Primary hook for accessing authentication state and user information.
 * This is the public API that all components should use.
 *
 * @module useAuth
 */

'use client';

import {
  useAuthContext,
  type User,
  type Role,
  type AuthContextValue,
} from '@/contexts/AuthContext';

/**
 * Hook to access authentication context.
 *
 * @returns Authentication context value with user info, loading state, and helper methods
 *
 * @throws {Error} If used outside of AuthProvider
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { user, isLoading, isAuthenticated, hasRole } = useAuth();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *   if (!isAuthenticated) return <div>Please log in</div>;
 *
 *   return (
 *     <div>
 *       <p>Welcome, {user.name}!</p>
 *       {hasRole('admin') && <AdminPanel />}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example
 * ```tsx
 * // Check if user is authenticated before rendering
 * function ProtectedContent() {
 *   const { isAuthenticated } = useAuth();
 *
 *   if (!isAuthenticated) {
 *     return <Navigate to="/sign-in" />;
 *   }
 *
 *   return <div>Protected content</div>;
 * }
 * ```
 *
 * @example
 * ```tsx
 * // Check user role for conditional rendering
 * function Dashboard() {
 *   const { user, hasRole } = useAuth();
 *
 *   return (
 *     <div>
 *       <h1>Dashboard</h1>
 *       {hasRole('admin') && (
 *         <AdminSection />
 *       )}
 *       {hasRole('normal') && (
 *         <UserSection />
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export function useAuth(): AuthContextValue {
  return useAuthContext();
}

// Re-export types for convenience
export type { User, Role, AuthContextValue };
