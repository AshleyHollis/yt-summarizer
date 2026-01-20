/**
 * Next.js 16 Proxy for Route Protection (Auth0 v4 SDK)
 *
 * This proxy handles authentication at the network boundary using the Auth0 SDK.
 * It automatically:
 * - Manages authentication cookies
 * - Handles auth redirects
 * - Protects routes based on configuration
 *
 * Public Routes (always accessible):
 * - /login
 * - /access-denied
 * - /auth/*
 *
 * Protected Routes:
 * - /admin/* - Requires authentication AND admin role (handled by custom RBAC logic)
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 * @see https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#protecting-routes-with-middleware
 */

import { NextResponse } from 'next/server';

/**
 * CRITICAL FIX: Do NOT import Auth0 at module level!
 * Static imports cause the Auth0 SDK to load during middleware initialization,
 * which can crash the app if Auth0 env vars are missing.
 *
 * Instead, use dynamic imports inside the function when needed.
 *
 * REMOVED: import { getAuth0Client, getAuth0Error } from './lib/auth0';
 */

/**
 * Determines if a route requires protection
 */
function shouldProtectRoute(pathname: string): boolean {
  // Admin routes require authentication and admin role
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
 * Proxy function (Next.js 16+)
 *
 * FIXED: Removed static Auth0 imports to prevent module-level SDK loading
 * Now uses dynamic imports only when auth is actually needed
 *
 * Original functionality:
 * - Checks authentication status
 * - Checks user roles for admin routes
 * - Redirects to /auth/login if unauthenticated
 * - Redirects to /access-denied if unauthorized
 *
 * Note: Uses standard Request type (not NextRequest) for Next.js 16 compatibility
 */
export async function proxy(request: Request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Skip auth checks for public routes
  if (isPublicRoute(pathname)) {
    return NextResponse.next();
  }

  // Skip auth checks for routes that don't need protection
  if (!shouldProtectRoute(pathname)) {
    return NextResponse.next();
  }

  // ONLY load Auth0 when we actually need to check authentication
  // This prevents the SDK from loading during app startup
  try {
    const { getAuth0Client } = await import('./lib/auth0');
    const auth0Client = await getAuth0Client();

    if (!auth0Client) {
      // Auth0 not configured - redirect to error page
      console.warn('[Proxy] Auth0 not configured, redirecting to error page');
      return NextResponse.redirect(new URL('/auth-config-error', request.url));
    }

    const session = await auth0Client.getSession();

    if (!session) {
      // Not authenticated - redirect to login
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
    // On error, redirect to error page
    return NextResponse.redirect(new URL('/auth-config-error', request.url));
  }
}

/**
 * Configure which routes run this proxy
 *
 * This matcher excludes:
 * - Static files (_next/static)
 * - Image optimization files (_next/image)
 * - Favicon and metadata files
 * - Azure SWA internal paths (/.swa/) - CRITICAL for SWA health checks
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     * - .swa (Azure Static Web Apps internal paths - health checks)
     */
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt|\\.swa).*)',
  ],
};
