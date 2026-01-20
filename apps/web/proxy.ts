import { auth0 } from './lib/auth0';

/**
 * Next.js 16 proxy layer that handles Auth0 authentication.
 * This proxy intercepts requests and automatically handles:
 * - /auth/login - Redirects to Auth0 login
 * - /auth/logout - Logs out user and clears session
 * - /auth/callback - Handles OAuth callback from Auth0
 * - /auth/profile - Returns user profile JSON
 * - /auth/access-token - Returns access token
 * - /auth/backchannel-logout - Handles backchannel logout
 *
 * All auth routes are handled by the Auth0 SDK automatically.
 *
 * Note: Next.js 16 uses proxy.ts (with standard Request) instead of
 * middleware.ts (with NextRequest) for the new proxy layer.
 */
export async function proxy(request: Request) {
  return await auth0.middleware(request);
}

/**
 * Matcher configuration to apply proxy to all routes except static assets.
 * Excludes:
 * - _next/static (Next.js static files)
 * - _next/image (Next.js Image Optimization files)
 * - favicon.ico
 * - sitemap.xml
 * - robots.txt
 */
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)'],
};
