/**
 * Auth0 API Route Handlers
 *
 * This file exports the Auth0 SDK's built-in route handlers for authentication flows.
 * It handles the following routes automatically:
 *   - GET /api/auth/login - Initiates login flow (redirects to Auth0 Universal Login)
 *   - GET /api/auth/logout - Logs out user and clears session
 *   - GET /api/auth/callback - OAuth callback handler (exchanges code for tokens)
 *   - GET /api/auth/me - Returns current user session
 *
 * @see https://github.com/auth0/nextjs-auth0#basic-setup
 * @see apps/web/src/lib/auth0.ts for client initialization
 */

import { auth0 } from '@/lib/auth0';

/**
 * GET handler for all Auth0 routes
 *
 * The Auth0 SDK provides a catch-all handler that routes requests to the
 * appropriate internal handler based on the URL path.
 *
 * Supported routes:
 *   - /api/auth/login?returnTo=/path - Initiate login with optional redirect
 *   - /api/auth/logout?returnTo=/path - Logout with optional redirect
 *   - /api/auth/callback?code=...&state=... - OAuth callback (automatic)
 *   - /api/auth/me - Get current session
 *
 * @example
 * ```typescript
 * // In a component
 * <a href="/api/auth/login?returnTo=/dashboard">Sign in</a>
 * <a href="/api/auth/logout">Sign out</a>
 *
 * // Fetch current session
 * const response = await fetch('/api/auth/me');
 * const user = await response.json();
 * ```
 */
export const GET = auth0.handleAuth();

/**
 * POST handler for Auth0 routes
 *
 * Some Auth0 operations (like token refresh) may use POST requests.
 * This ensures those operations work correctly.
 */
export const POST = auth0.handleAuth();
