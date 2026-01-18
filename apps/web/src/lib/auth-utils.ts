/**
 * Auth Utility Functions
 * 
 * Pure utility functions for authentication and authorization logic.
 * These functions have no side effects and are easily testable.
 * 
 * @module auth-utils
 */

import { User, Role } from '@/contexts/AuthContext';

/**
 * Check if user has a specific role.
 * 
 * @param user - User object (or null)
 * @param role - Role to check
 * @returns True if user has the role, false otherwise
 * 
 * @remarks
 * This is a pure function with no side effects. It can be used anywhere
 * role checks are needed, including middleware, server components, and client components.
 * 
 * @example
 * ```typescript
 * const user = await getSession();
 * 
 * if (hasRole(user, 'admin')) {
 *   // Show admin features
 * }
 * ```
 * 
 * @example
 * ```typescript
 * // In middleware
 * const user = await getSession();
 * if (!hasRole(user, 'admin') && isAdminRoute(request.url)) {
 *   return NextResponse.redirect(new URL('/access-denied', request.url));
 * }
 * ```
 * 
 * @example
 * ```typescript
 * // Multiple role check
 * function canModerate(user: User | null): boolean {
 *   return hasRole(user, 'admin') || hasRole(user, 'moderator');
 * }
 * ```
 */
export function hasRole(user: User | null, role: Role): boolean {
  if (!user) {
    return false;
  }
  
  return user['https://yt-summarizer.com/role'] === role;
}

/**
 * Get authentication method from user.sub.
 * 
 * @param sub - User subject identifier (user.sub)
 * @returns 'social' for OAuth providers, 'database' for username/password
 * 
 * @remarks
 * Auth0 uses different prefixes in the `sub` field to identify the authentication method:
 * - `auth0|...` - Database connection (username/password)
 * - `google-oauth2|...` - Google OAuth
 * - `github|...` - GitHub OAuth
 * - etc.
 * 
 * @example
 * ```typescript
 * const method = getAuthMethod('google-oauth2|123456'); // Returns 'social'
 * const method = getAuthMethod('auth0|abc123'); // Returns 'database'
 * 
 * if (method === 'social') {
 *   console.log('User signed in with a social provider');
 * }
 * ```
 * 
 * @example
 * ```typescript
 * // Conditional UI based on auth method
 * function ProfileSettings({ user }: { user: User }) {
 *   const method = getAuthMethod(user.sub);
 *   
 *   return (
 *     <div>
 *       {method === 'database' && (
 *         <button>Change Password</button>
 *       )}
 *       {method === 'social' && (
 *         <p>Password managed by {getProvider(user.sub)}</p>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export function getAuthMethod(sub: string): 'social' | 'database' {
  if (sub.startsWith('auth0|')) {
    return 'database';
  }
  return 'social';
}

/**
 * Get provider name from user.sub.
 * 
 * @param sub - User subject identifier (user.sub)
 * @returns Provider name (e.g., 'google-oauth2', 'github', 'auth0')
 * 
 * @remarks
 * Extracts the provider prefix from the Auth0 subject identifier.
 * 
 * @example
 * ```typescript
 * const provider = getProvider('google-oauth2|123456'); // Returns 'google-oauth2'
 * const provider = getProvider('github|789012'); // Returns 'github'
 * const provider = getProvider('auth0|abc'); // Returns 'auth0'
 * ```
 * 
 * @example
 * ```typescript
 * // Display provider-specific UI
 * function LoginHistory({ user }: { user: User }) {
 *   const provider = getProvider(user.sub);
 *   const displayName = {
 *     'google-oauth2': 'Google',
 *     'github': 'GitHub',
 *     'auth0': 'Email/Password'
 *   }[provider] || provider;
 *   
 *   return <p>Signed in with: {displayName}</p>;
 * }
 * ```
 */
export function getProvider(sub: string): string {
  const [provider] = sub.split('|');
  return provider;
}

/**
 * Get user's display name.
 * 
 * @param user - User object (or null)
 * @returns Display name (prioritizes name, falls back to email, then 'User')
 * 
 * @remarks
 * Provides a consistent way to get a user-friendly name for display.
 * Social providers typically provide a name, while database users may not.
 * 
 * @example
 * ```typescript
 * const user = await getSession();
 * const displayName = getUserDisplayName(user); // "John Doe" or "user@example.com" or "User"
 * 
 * return <p>Welcome, {displayName}!</p>;
 * ```
 */
export function getUserDisplayName(user: User | null): string {
  if (!user) {
    return 'User';
  }
  
  if (user.name) {
    return user.name;
  }
  
  if (user.username) {
    return user.username;
  }
  
  return user.email;
}

/**
 * Check if user is authenticated (helper for null checks).
 * 
 * @param user - User object (or null)
 * @returns True if user is not null
 * 
 * @remarks
 * Simple type guard for user authentication checks.
 * 
 * @example
 * ```typescript
 * const user = await getSession();
 * 
 * if (isAuthenticated(user)) {
 *   // TypeScript knows user is not null here
 *   console.log(user.email);
 * }
 * ```
 */
export function isAuthenticated(user: User | null): user is User {
  return user !== null;
}

/**
 * Get user's role.
 * 
 * @param user - User object (or null)
 * @returns User's role, or null if not authenticated
 * 
 * @example
 * ```typescript
 * const user = await getSession();
 * const role = getUserRole(user); // 'admin' | 'normal' | null
 * 
 * if (role === 'admin') {
 *   // Show admin features
 * }
 * ```
 */
export function getUserRole(user: User | null): Role | null {
  if (!user) {
    return null;
  }
  
  return user['https://yt-summarizer.com/role'];
}
