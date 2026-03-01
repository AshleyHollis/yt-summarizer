/**
 * Auth Context
 *
 * Provides authentication state and user information to the application.
 * This context wraps the Auth0 SDK and provides a simplified interface.
 *
 * @module AuthContext
 */

'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { getClientApiUrl } from '@/services/runtimeConfig';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * User role enumeration.
 *
 * @remarks
 * Adding new roles requires:
 * 1. Update this type definition
 * 2. Update Terraform user provisioning (app_metadata)
 * 3. Update Auth0 Action to include new role in token claims
 * 4. Update authorization checks in middleware and components
 */
export type Role = 'admin' | 'normal';

/**
 * User profile information from Auth0.
 *
 * @remarks
 * The `sub` (subject) field is the unique identifier for the user across the system.
 * The role is stored as a custom claim with namespaced key.
 */
export interface User {
  /** Unique user identifier (Auth0 format: provider|id) */
  sub: string;

  /** User's email address */
  email: string;

  /** Whether email has been verified */
  email_verified: boolean;

  /** User's display name (optional, from social providers) */
  name?: string;

  /** Profile picture URL (optional, from social providers) */
  picture?: string;

  /** Username (optional, for database connection users) */
  username?: string;

  /** User role (custom claim, namespaced) */
  'https://yt-summarizer.com/role': Role;

  /** Last profile update timestamp (ISO 8601) */
  updated_at: string;
}

/**
 * Active user session with authentication tokens.
 *
 * @remarks
 * Sessions are stored in encrypted HTTP-only cookies managed by @auth0/nextjs-auth0.
 * The application code should not directly manipulate session storage.
 */
export interface Session {
  /** User profile information */
  user: User;

  /** JWT access token for API calls */
  accessToken: string;

  /** Refresh token for token renewal (optional, may not be present) */
  refreshToken?: string;

  /** OpenID Connect ID token */
  idToken: string;

  /** Token type (always "Bearer") */
  tokenType: 'Bearer';

  /** Access token expiration time (Unix timestamp in seconds) */
  expiresAt: number;
}

/**
 * Authentication context value provided to React components.
 *
 * @remarks
 * Access via `useAuth()` hook. Do not import Auth0 SDK directly in components.
 */
export interface AuthContextValue {
  /** Current user (null if not authenticated) */
  user: User | null;

  /** Whether authentication state is loading */
  isLoading: boolean;

  /** Authentication error (if any) */
  error: Error | null;

  /** Whether user is authenticated */
  isAuthenticated: boolean;

  /** Check if user has specific role */
  hasRole: (role: Role) => boolean;
}

// ============================================================================
// Context Creation
// ============================================================================

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// ============================================================================
// Provider Component (Placeholder for T017 implementation)
// ============================================================================

interface AuthProviderProps {
  children: ReactNode;
}

/**
 * Auth Provider Component
 *
 * Wraps the application and provides authentication context to all child components.
 * This component integrates with Auth0 via client-side API calls to `/api/auth/me`.
 *
 * @param props - Component props
 * @param props.children - Child components to wrap with auth context
 * @returns Provider component with authentication state
 *
 * @remarks
 * **Usage**:
 * ```tsx
 * // In root layout (apps/web/src/app/layout.tsx)
 * export default function RootLayout({ children }) {
 *   return (
 *     <AuthProvider>
 *       {children}
 *     </AuthProvider>
 *   );
 * }
 * ```
 *
 * **State Management**:
 * - Automatically fetches user session on mount
 * - Handles loading, error, and authenticated states
 * - Re-validates session on component mount (not on every render)
 *
 * **Error Handling**:
 * - 401/403 responses are treated as "not authenticated" (normal)
 * - Other HTTP errors are captured in `error` state
 * - Network errors are logged to console and captured in `error` state
 *
 * **Session Storage**:
 * - Session is stored in encrypted HTTP-only cookie (managed by Auth0 SDK)
 * - This component does not directly manipulate session storage
 * - Session cookie is automatically sent with `/api/auth/me` requests
 *
 * @example
 * // Accessing auth state in a component
 * function MyComponent() {
 *   const { user, isLoading, isAuthenticated, hasRole } = useAuth();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *   if (!isAuthenticated) return <div>Please log in</div>;
 *
 *   return (
 *     <div>
 *       <p>Welcome, {user.name}</p>
 *       {hasRole('admin') && <AdminPanel />}
 *     </div>
 *   );
 * }
 *
 * @see {@link useAuth} for accessing auth state in components
 * @see {@link AuthContextValue} for available context properties
 * @see {@link User} for user profile structure
 *
 * Implementation: T017
 */
export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | null>(null);

  // Fetch user session from backend API
  useEffect(() => {
    let mounted = true;

    async function fetchUser() {
      try {
        setIsLoading(true);
        setError(null);

        // Call the backend API session endpoint directly
        // Uses runtime config to get the correct backend URL
        const apiUrl = getClientApiUrl();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(`${apiUrl}/api/auth/session`, {
          signal: controller.signal,
          credentials: 'include',
          headers: { 'Accept': 'application/json' },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          // Any non-200 response means not authenticated
          if (mounted) {
            setUser(null);
            setIsLoading(false);
          }
          return;
        }

        const data = await response.json();

        if (mounted) {
          setUser(data.user || null);
          setIsLoading(false);
        }
      } catch (err) {
        // Handle timeout gracefully - treat as not authenticated
        if (err instanceof Error && err.name === 'AbortError') {
          console.warn('Auth session check timed out - treating as not authenticated');
          if (mounted) {
            setUser(null);
            setIsLoading(false);
          }
          return;
        }

        console.error('Error fetching user session:', err);
        if (mounted) {
          setError(err instanceof Error ? err : new Error('Unknown error fetching user'));
          setUser(null);
          setIsLoading(false);
        }
      }
    }

    fetchUser();

    // Cleanup function to prevent state updates after unmount
    return () => {
      mounted = false;
    };
  }, []);

  /**
   * Check if the current user has a specific role.
   *
   * @param role - The role to check (e.g., 'admin', 'normal')
   * @returns `true` if user is authenticated and has the specified role, `false` otherwise
   *
   * @remarks
   * - Returns `false` if user is not authenticated (user === null)
   * - Role is retrieved from custom claim 'https://yt-summarizer.com/role'
   * - Role claim is added by Auth0 Action 'add-roles-to-tokens' during login
   *
   * @example
   * ```tsx
   * const { hasRole } = useAuth();
   *
   * // Conditional rendering based on role
   * {hasRole('admin') && <AdminPanel />}
   *
   * // Navigation guard
   * if (!hasRole('admin')) {
   *   router.push('/forbidden');
   * }
   * ```
   */
  const hasRole = (role: Role): boolean => {
    if (!user) return false;
    return user['https://yt-summarizer.com/role'] === role;
  };

  const value: AuthContextValue = {
    user,
    isLoading,
    error,
    isAuthenticated: user !== null,
    hasRole,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ============================================================================
// Context Hook (Implementation in useAuth.ts - T006)
// ============================================================================

/**
 * Hook to access authentication context.
 *
 * **IMPORTANT**: Use the `useAuth()` hook from `hooks/useAuth.ts` instead.
 * This is a low-level internal hook. The `useAuth()` hook provides the same
 * functionality with better ergonomics.
 *
 * @throws {Error} If used outside of AuthProvider
 * @returns Authentication context value
 *
 * @remarks
 * This hook provides access to:
 * - `user`: Current user profile (null if not authenticated)
 * - `isLoading`: Whether auth state is being loaded
 * - `error`: Any authentication error that occurred
 * - `isAuthenticated`: Whether a user is currently logged in
 * - `hasRole(role)`: Function to check if user has a specific role
 *
 * @example
 * ```tsx
 * import { useAuthContext } from '@/contexts/AuthContext';
 *
 * function MyComponent() {
 *   const { user, isLoading, isAuthenticated, hasRole } = useAuthContext();
 *
 *   if (isLoading) {
 *     return <div>Loading authentication...</div>;
 *   }
 *
 *   if (!isAuthenticated) {
 *     return <div>Please log in to continue</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <h1>Welcome, {user.name || user.email}</h1>
 *       {hasRole('admin') && (
 *         <a href="/admin">Admin Dashboard</a>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @see {@link useAuth} - Recommended hook to use in components (apps/web/src/hooks/useAuth.ts)
 * @see {@link AuthProvider} - Provider component that must wrap your app
 * @see {@link AuthContextValue} - Type definition for context value
 */
export function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}
