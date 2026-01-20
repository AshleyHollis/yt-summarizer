/**
 * Auth0 SDK Route Handler
 *
 * This dynamic route handles all Auth0 authentication endpoints:
 * - GET /api/auth/login - Initiates Auth0 login flow
 * - GET /api/auth/logout - Clears session and logs out
 * - GET /api/auth/callback - Handles OAuth callback from Auth0
 * - GET /api/auth/me - Returns current user session
 *
 * @see https://github.com/auth0/nextjs-auth0
 *
 * ## Configuration
 *
 * Required environment variables:
 * - AUTH0_SECRET - Random string for session encryption (32+ chars)
 * - AUTH0_BASE_URL - Public URL of the application
 * - AUTH0_ISSUER_BASE_URL - Auth0 tenant domain (https://{tenant}.auth0.com)
 * - AUTH0_CLIENT_ID - Auth0 application client ID
 * - AUTH0_CLIENT_SECRET - Auth0 application client secret
 *
 * @module api/auth/[auth0]
 */

import { handleAuth } from '@auth0/nextjs-auth0';
import { NextResponse } from 'next/server';

// Check if Auth0 is properly configured
const isAuth0Configured = Boolean(
  process.env.AUTH0_SECRET &&
  process.env.AUTH0_BASE_URL &&
  process.env.AUTH0_ISSUER_BASE_URL &&
  process.env.AUTH0_CLIENT_ID &&
  process.env.AUTH0_CLIENT_SECRET
);

/**
 * Handle GET requests to Auth0 routes.
 *
 * During SWA warmup or if Auth0 is not configured, this returns a graceful
 * "not authenticated" response instead of crashing.
 */
export const GET = async (req: Request) => {
  // If Auth0 is not configured (e.g., during SWA warmup before env vars are set),
  // return a "not authenticated" response to prevent hanging
  if (!isAuth0Configured) {
    const url = new URL(req.url);
    const path = url.pathname;

    // For /api/auth/me, return 401 (not authenticated)
    if (path.includes('/me')) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // For other auth routes (login, logout, callback), return 503 (service unavailable)
    return NextResponse.json(
      { error: 'Auth0 not configured. Please check environment variables.' },
      { status: 503 }
    );
  }

  // Auth0 is configured, use the SDK handler
  return handleAuth()(req);
};
