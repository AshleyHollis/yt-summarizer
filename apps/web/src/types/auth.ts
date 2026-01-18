/**
 * Authentication Error Types
 * 
 * Defines custom error classes for authentication-related failures.
 * Each error type represents a specific failure mode with clear semantics.
 * 
 * @module auth-errors
 */

import { Role } from '@/contexts/AuthContext';

/**
 * Base authentication error.
 * 
 * @remarks
 * All auth-related errors extend this base class for consistent error handling.
 * Follows single responsibility principle (FR-034): one error type per failure mode.
 * 
 * @example
 * ```typescript
 * try {
 *   await someAuthOperation();
 * } catch (error) {
 *   if (error instanceof AuthError) {
 *     console.log(`Auth error [${error.code}]:`, error.message);
 *   }
 * }
 * ```
 */
export class AuthError extends Error {
  /**
   * Creates a new AuthError.
   * 
   * @param message - Human-readable error message
   * @param code - Machine-readable error code
   * @param statusCode - HTTP status code (default: 500)
   */
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'AuthError';
    
    // Maintain proper stack trace in V8 engines
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthError);
    }
  }
}

/**
 * Session expired error.
 * 
 * @remarks
 * Thrown when a user's session has expired during active use.
 * UI should redirect to login with "Session expired" message and preserve
 * the intended destination URL for post-login redirect.
 * 
 * See: FR-015a (Session expiration handling)
 * 
 * @example
 * ```typescript
 * if (sessionExpired) {
 *   throw new SessionExpiredError();
 * }
 * 
 * // In error boundary or catch block:
 * if (error instanceof SessionExpiredError) {
 *   router.push(`/login?returnTo=${currentPath}&message=session-expired`);
 * }
 * ```
 */
export class SessionExpiredError extends AuthError {
  /**
   * Creates a new SessionExpiredError.
   * 
   * @param message - Custom message (default: "Your session has expired. Please log in again.")
   */
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
 * Typically used for role-based access control violations.
 * 
 * See: FR-007 (Protect admin-only routes)
 * 
 * @example
 * ```typescript
 * function AdminDashboard() {
 *   const { hasRole } = useAuth();
 *   
 *   if (!hasRole('admin')) {
 *     throw new UnauthorizedError('Admin access required', 'admin');
 *   }
 *   
 *   return <div>Admin Dashboard</div>;
 * }
 * ```
 * 
 * @example
 * ```typescript
 * // In middleware
 * if (user.role !== 'admin' && isAdminRoute(path)) {
 *   throw new UnauthorizedError(
 *     'You do not have permission to access this page',
 *     'admin'
 *   );
 * }
 * ```
 */
export class UnauthorizedError extends AuthError {
  /**
   * Creates a new UnauthorizedError.
   * 
   * @param message - Custom message (default: generic permission denied message)
   * @param requiredRole - Role required to access the resource (optional)
   */
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
 * UI should display inline error with retry option and choice of different provider.
 * 
 * See: FR-015b (OAuth failure error handling)
 * 
 * @example
 * ```typescript
 * // In OAuth callback handler
 * if (error === 'access_denied') {
 *   throw new OAuthError('You denied the login request.', 'google');
 * }
 * 
 * // In error boundary:
 * if (error instanceof OAuthError) {
 *   return (
 *     <div>
 *       <p>{error.message}</p>
 *       {error.provider && <p>Provider: {error.provider}</p>}
 *       <button onClick={() => retry()}>Try again</button>
 *       <button onClick={() => chooseOtherProvider()}>Use different method</button>
 *     </div>
 *   );
 * }
 * ```
 */
export class OAuthError extends AuthError {
  /**
   * Creates a new OAuthError.
   * 
   * @param message - Custom message (default: generic OAuth failure message)
   * @param provider - OAuth provider name (e.g., 'google', 'github')
   */
  constructor(
    message: string = 'Authentication failed. Please try again.',
    public provider?: string
  ) {
    super(message, 'OAUTH_FAILED', 400);
    this.name = 'OAuthError';
  }
}

/**
 * Type guard to check if an error is an AuthError or subclass.
 * 
 * @param error - Error to check
 * @returns True if error is an AuthError instance
 * 
 * @example
 * ```typescript
 * try {
 *   await authenticate();
 * } catch (error) {
 *   if (isAuthError(error)) {
 *     console.log(`Auth error code: ${error.code}`);
 *   } else {
 *     console.log('Non-auth error:', error);
 *   }
 * }
 * ```
 */
export function isAuthError(error: unknown): error is AuthError {
  return error instanceof AuthError;
}

/**
 * Get user-friendly error message from any error.
 * 
 * @param error - Error to extract message from
 * @returns User-friendly error message
 * 
 * @example
 * ```typescript
 * try {
 *   await authenticate();
 * } catch (error) {
 *   toast.error(getErrorMessage(error));
 * }
 * ```
 */
export function getErrorMessage(error: unknown): string {
  if (isAuthError(error)) {
    return error.message;
  }
  
  if (error instanceof Error) {
    return error.message;
  }
  
  return 'An unknown error occurred';
}
