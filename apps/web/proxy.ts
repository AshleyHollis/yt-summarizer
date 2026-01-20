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
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
};
