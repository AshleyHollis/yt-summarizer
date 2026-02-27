/**
 * TypeScript Type Contracts for Auth0 UI Integration
 *
 * These types define the public API contract for authentication functionality.
 * All consumers of the auth module should import from this file.
 *
 * @module auth-contracts
 */

// ============================================================================
// User Types
// ============================================================================

/**
 * User profile information from Auth0.
 *
 * @remarks
 * The `sub` (subject) field is the unique identifier for the user across the system.
 * The role is stored as a custom claim with namespaced key.
 *
 * @example
 * ```typescript
 * const user: User = {
 *   sub: "google-oauth2|123456789",
 *   email: "user@example.com",
 *   email_verified: true,
 *   name: "John Doe",
 *   picture: "https://lh3.googleusercontent.com/...",
 *   "https://yt-summarizer.com/role": "admin",
 *   updated_at: "2026-01-19T10:30:00.000Z"
 * };
 * ```
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
 * User role enumeration.
 *
 * @remarks
 * Adding new roles requires:
 * 1. Update this type definition
 * 2. Update Terraform user provisioning (app_metadata)
 * 3. Update Auth0 Action to include new role in token claims
 * 4. Update authorization checks in middleware and components
 *
 * See: FR-029, FR-030, SC-018 in spec.md
 */
export type Role = 'admin' | 'normal';

// ============================================================================
// Session Types
// ============================================================================

/**
 * Active user session with authentication tokens.
 *
 * @remarks
 * Sessions are stored in encrypted HTTP-only cookies managed by @auth0/nextjs-auth0.
 * The application code should not directly manipulate session storage.
 *
 * @example
 * ```typescript
 * const session = await getSession();
 * if (session) {
 *   console.log('User:', session.user.email);
 *   console.log('Expires at:', new Date(session.expiresAt * 1000));
 * }
 * ```
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

// ============================================================================
// Auth Context Types
// ============================================================================

/**
 * Authentication context value provided to React components.
 *
 * @remarks
 * Access via `useAuth()` hook. Do not import Auth0 SDK directly in components.
 *
 * @example
 * ```typescript
 * function MyComponent() {
 *   const { user, isLoading, error } = useAuth();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *   if (error) return <div>Error: {error.message}</div>;
 *   if (!user) return <div>Please log in</div>;
 *
 *   return <div>Welcome, {user.name}!</div>;
 * }
 * ```
 */
export interface AuthContextValue {
  /** Current user (null if not authenticated) */
  user: User | null;

  /** Whether authentication state is loading */
  isLoading: boolean;

  /** Authentication error (if any) */
  error: AuthError | null;

  /** Whether user is authenticated */
  isAuthenticated: boolean;

  /** Check if user has specific role */
  hasRole: (role: Role) => boolean;
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Base authentication error.
 *
 * @remarks
 * All auth-related errors extend this base class for consistent error handling.
 * See: FR-034 (single responsibility principle for error types)
 */
export class AuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Session expired error.
 *
 * @remarks
 * Thrown when a user's session has expired during active use.
 * UI should redirect to login with "Session expired" message.
 * See: FR-015a
 */
export class SessionExpiredError extends AuthError {
  constructor(message: string = 'Your session has expired. Please log in again.') {
    super(message, 'SESSION_EXPIRED', 401);
    this.name = 'SessionExpiredError';
  }
}

/**
 * Unauthorized access error.
 *
 * @remarks
 * Thrown when a user attempts to access a resource they don't have permission for.
 * See: FR-007
 */
export class UnauthorizedError extends AuthError {
  constructor(
    message: string = 'You do not have permission to access this resource.',
    public requiredRole?: Role
  ) {
    super(message, 'UNAUTHORIZED', 403);
    this.name = 'UnauthorizedError';
  }
}

/**
 * OAuth authentication failed error.
 *
 * @remarks
 * Thrown when OAuth flow fails (user denies consent, provider error, etc.).
 * UI should display inline error with retry option.
 * See: FR-015b
 */
export class OAuthError extends AuthError {
  constructor(
    message: string = 'Authentication failed. Please try again.',
    public provider?: string
  ) {
    super(message, 'OAUTH_FAILED', 400);
    this.name = 'OAuthError';
  }
}

// ============================================================================
// Auth Utility Types
// ============================================================================

/**
 * Login options for initiating authentication flow.
 */
export interface LoginOptions {
  /** URL to redirect to after successful login */
  returnTo?: string;

  /** Specific Auth0 connection to use (bypasses Universal Login) */
  connection?: 'google-oauth2' | 'github' | 'Username-Password-Authentication';
}

/**
 * Logout options.
 */
export interface LogoutOptions {
  /** URL to redirect to after logout (must be in allowed logout URLs) */
  returnTo?: string;
}

/**
 * Authentication method type (derived from user.sub).
 */
export type AuthMethod = 'social' | 'database';

/**
 * Provider name (derived from user.sub).
 */
export type Provider = 'google-oauth2' | 'github' | 'auth0';

// ============================================================================
// Component Prop Types
// ============================================================================

/**
 * Props for components that require authentication.
 */
export interface RequireAuthProps {
  /** User must have this role to access the component */
  requiredRole?: Role;

  /** Fallback component to render if not authorized */
  fallback?: React.ReactNode;

  /** URL to redirect to if not authenticated */
  redirectTo?: string;
}

/**
 * Props for login button component.
 */
export interface LoginButtonProps {
  /** Login options */
  options?: LoginOptions;

  /** Custom button text */
  children?: React.ReactNode;

  /** Custom CSS classes */
  className?: string;
}

/**
 * Props for logout button component.
 */
export interface LogoutButtonProps {
  /** Logout options */
  options?: LogoutOptions;

  /** Custom button text */
  children?: React.ReactNode;

  /** Custom CSS classes */
  className?: string;
}

/**
 * Props for user profile component.
 */
export interface UserProfileProps {
  /** Whether to show full profile or just avatar */
  variant?: 'full' | 'compact';

  /** Custom CSS classes */
  className?: string;
}

// ============================================================================
// Test Account Types
// ============================================================================

/**
 * Test account credentials (for E2E testing).
 *
 * @remarks
 * These credentials are stored in Azure Key Vault and retrieved during test execution.
 * Never commit these values to source control.
 */
export interface TestAccount {
  /** Test account email */
  email: string;

  /** Test account password (retrieved from Key Vault) */
  password: string;

  /** Account role */
  role: Role;

  /** Auth0 connection name */
  connection: 'Username-Password-Authentication';
}

// ============================================================================
// Exported Utility Functions (Type Signatures)
// ============================================================================

/**
 * Check if user has a specific role.
 *
 * @param user - User object (or null)
 * @param role - Role to check
 * @returns True if user has the role, false otherwise
 *
 * @example
 * ```typescript
 * if (hasRole(user, 'admin')) {
 *   // Show admin features
 * }
 * ```
 */
export function hasRole(user: User | null, role: Role): boolean;

/**
 * Get authentication method from user.sub.
 *
 * @param sub - User subject identifier
 * @returns 'social' for OAuth providers, 'database' for username/password
 *
 * @example
 * ```typescript
 * const method = getAuthMethod('google-oauth2|123'); // 'social'
 * const method = getAuthMethod('auth0|abc'); // 'database'
 * ```
 */
export function getAuthMethod(sub: string): AuthMethod;

/**
 * Get provider name from user.sub.
 *
 * @param sub - User subject identifier
 * @returns Provider name
 *
 * @example
 * ```typescript
 * const provider = getProvider('google-oauth2|123'); // 'google-oauth2'
 * const provider = getProvider('github|456'); // 'github'
 * ```
 */
export function getProvider(sub: string): Provider;
