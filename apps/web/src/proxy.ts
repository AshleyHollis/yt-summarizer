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
import { getAuth0Client, getAuth0Error } from './lib/auth0';

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
 * TEMPORARY: Bypassed for SWA warmup timeout investigation
 * See: apps/web/SWA-WARMUP-NEXT-STEPS.md
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
  console.log('[Proxy] BYPASSED - Testing SWA warmup issue (middleware disabled)');
  console.log('[Proxy] Request path:', new URL(request.url).pathname);

  // TEMPORARY: Bypass ALL auth logic to test if middleware is causing warmup timeout
  // If deployment succeeds with this change, the issue is in the proxy middleware
  // If deployment still fails, the issue is elsewhere (likely next.config.ts or module loading)
  return NextResponse.next();
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
