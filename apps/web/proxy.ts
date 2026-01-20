/**
 * Auth0 Proxy Handler (Next.js 16+)
 *
 * This proxy intercepts authentication requests at the network boundary
 * and handles Auth0 authentication flows.
 *
 * Automatic Routes (handled by Auth0 SDK middleware):
 * - /auth/login - Initiate login flow
 * - /auth/logout - End session
 * - /auth/callback - OAuth callback handler
 * - /auth/profile - Get user profile (built-in SDK route)
 *
 * IMPORTANT: Only runs on /auth/* routes to avoid warmup timeouts.
 * Auth0 requires environment variables that are set AFTER deployment,
 * so we must narrow the matcher to avoid running on warmup health checks.
 *
 * @see https://github.com/auth0/nextjs-auth0#readme
 */

import { getAuth0Client } from './src/lib/auth0';

export async function proxy(request: Request) {
  const client = getAuth0Client();

  // If Auth0 is not configured, pass through the request
  if (!client) {
    console.warn('[Proxy] Auth0 not configured - skipping authentication middleware');
    return;
  }

  // Let Auth0 SDK handle authentication routes
  return await client.middleware(request);
}

export const config = {
  matcher: [
    /*
     * CRITICAL: Only match /auth/* routes to avoid SWA warmup timeout.
     *
     * During SWA deployment, Azure performs warmup health checks to "/", "/health", etc.
     * Auth0 environment variables are only available AFTER deployment completes.
     * If proxy runs on warmup requests, getAuth0Client() may cause timeouts.
     *
     * By narrowing to /auth/*, warmup requests skip this proxy entirely.
     */
    '/auth/:path*',
  ],
};
