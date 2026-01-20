/**
 * Next.js 16 Proxy for Auth0 Authentication and Route Protection
 *
 * This unified proxy handles:
 * 1. Auth0 authentication flows (/auth/* routes)
 * 2. Route protection for admin routes
 *
 * Auth0 Automatic Routes:
 * - /auth/login - Initiate login flow
 * - /auth/logout - End session
 * - /auth/callback - OAuth callback handler
 * - /auth/profile - Get user profile
 *
 * Protected Routes:
 * - /admin/* - Requires authentication AND admin role
 *
 * CRITICAL for Azure SWA:
 * - Uses dynamic imports to prevent loading Auth0 SDK at startup
 * - Checks isAuth0Configured() BEFORE loading SDK
 * - Matcher excludes health check paths to prevent warmup timeout
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 * @see https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md
 */

import { NextResponse } from 'next/server';

/**
 * Determines if a route requires protection
 */
function shouldProtectRoute(pathname: string): boolean {
  const adminRoutes = ['/admin'];
  return adminRoutes.some((route) => pathname.startsWith(route));
}

/**
 * Public routes that should never be protected
 */
function isPublicRoute(pathname: string): boolean {
  const publicRoutes = ['/login', '/access-denied', '/auth'];
  return publicRoutes.some((route) => pathname.startsWith(route));
}

/**
 * Checks if a user has the admin role
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hasAdminRole(session: any): boolean {
  if (!session || !session.user) {
    return false;
  }
  const role = session.user['https://yt-summarizer.com/role'];
  return role === 'admin';
}

/**
 * Unified Proxy function (Next.js 16+)
 *
 * Handles both:
 * 1. Auth0 authentication routes (/auth/*)
 * 2. Admin route protection (/admin/*)
 *
 * CRITICAL: Uses dynamic imports to avoid loading Auth0 SDK at module init time.
 * The isAuth0Configured() check happens BEFORE importing the SDK.
 */
export async function proxy(request: Request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // ============================================================
  // PART 1: Handle Auth0 authentication routes (/auth/*)
  // ============================================================
  if (pathname.startsWith('/auth/')) {
    // Dynamic import to prevent loading Auth0 SDK at module initialization
    const { isAuth0Configured } = await import('./lib/auth0');

    // Check if Auth0 is configured BEFORE loading the client
    if (!isAuth0Configured()) {
      console.warn('[Proxy] Auth0 not configured - skipping auth middleware for', pathname);
      // Return 503 Service Unavailable for auth routes when not configured
      return new Response('Authentication service not configured', { status: 503 });
    }

    // Only now load the full Auth0 client
    const { getAuth0Client } = await import('./lib/auth0');
    const client = await getAuth0Client();

    if (!client) {
      console.warn('[Proxy] Auth0 client failed to initialize');
      return new Response('Authentication service unavailable', { status: 503 });
    }

    // Let Auth0 SDK handle authentication routes
    return await client.middleware(request);
  }

  // ============================================================
  // PART 2: Handle route protection
  // ============================================================

  // Skip auth checks for public routes
  if (isPublicRoute(pathname)) {
    return NextResponse.next();
  }

  // Skip auth checks for routes that don't need protection
  if (!shouldProtectRoute(pathname)) {
    return NextResponse.next();
  }

  // ONLY load Auth0 when we actually need to check authentication
  try {
    const { isAuth0Configured } = await import('./lib/auth0');

    // Check if Auth0 is configured BEFORE loading the client
    if (!isAuth0Configured()) {
      console.warn('[Proxy] Auth0 not configured, redirecting to error page');
      return NextResponse.redirect(new URL('/auth-config-error', request.url));
    }

    const { getAuth0Client } = await import('./lib/auth0');
    const auth0Client = await getAuth0Client();

    if (!auth0Client) {
      console.warn('[Proxy] Auth0 client failed to initialize, redirecting to error page');
      return NextResponse.redirect(new URL('/auth-config-error', request.url));
    }

    const session = await auth0Client.getSession();

    if (!session) {
      console.log('[Proxy] User not authenticated, redirecting to login');
      return NextResponse.redirect(new URL('/auth/login', request.url));
    }

    // Check admin access for admin routes
    if (pathname.startsWith('/admin') && !hasAdminRole(session)) {
      console.log('[Proxy] User lacks admin role, redirecting to access denied');
      return NextResponse.redirect(new URL('/access-denied', request.url));
    }

    // Authenticated and authorized
    return NextResponse.next();
  } catch (error) {
    console.error('[Proxy] Error checking authentication:', error);
    return NextResponse.redirect(new URL('/auth-config-error', request.url));
  }
}

/**
 * Configure which routes run this proxy
 *
 * CRITICAL FOR SWA WARMUP:
 * - Excludes Azure SWA health check paths (robots*.txt pattern)
 * - Excludes static files and metadata
 * - Only matches routes that need auth handling
 *
 * The matcher is intentionally narrow to ensure:
 * 1. SWA warmup health checks (/robots933456.txt) skip the proxy entirely
 * 2. The Auth0 SDK is never loaded during warmup
 */
export const config = {
  matcher: [
    // Match /auth/* for Auth0 authentication handling
    '/auth/:path*',
    // Match /admin/* for route protection
    '/admin/:path*',
  ],
};
