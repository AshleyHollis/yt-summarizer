/**
 * Next.js 16 Proxy — Route Protection Middleware
 *
 * This proxy runs on the Node.js runtime at the network boundary, before routing.
 * It handles two responsibilities:
 *   1. Auth route delegation: Forwards /api/auth/* to Auth0 SDK (login, logout, callback)
 *   2. Admin route protection: Blocks unauthenticated or non-admin access to /admin/*
 *
 * The Auth0 client is lazily initialized (dynamic import) to avoid SWA warmup timeouts.
 * If Auth0 is not configured, auth routes pass through and admin routes fall through to
 * the page-level client-side guard.
 *
 * @see apps/web/src/app/admin/page.tsx for the client-side guard (defense in depth)
 */

import { NextResponse, type NextRequest } from 'next/server';
import { getAuth0Client } from '@/lib/auth0';

/** Auth0 built-in routes that the SDK handles (login, logout, callback). */
const AUTH0_ROUTES = ['/api/auth/login', '/api/auth/logout', '/api/auth/callback'];

/**
 * Proxy handler — the entry point for Next.js 16 proxy middleware.
 *
 * @param request - Incoming HTTP request (standard Request, cast to NextRequest for Auth0)
 */
export async function proxy(request: Request) {
  const req = request as NextRequest;
  const { pathname } = new URL(request.url);

  // ─── Auth0 route delegation ────────────────────────────────────────────────
  // Let the Auth0 SDK handle login / logout / callback.
  const isAuth0Route = AUTH0_ROUTES.some((route) => pathname.startsWith(route));
  if (isAuth0Route) {
    try {
      const client = await getAuth0Client();
      if (client) {
        return await client.middleware(req);
      }
    } catch (err) {
      console.error('[proxy] Auth0 middleware error on auth route:', err);
    }
    return NextResponse.next();
  }

  // ─── Admin route protection ────────────────────────────────────────────────
  if (pathname.startsWith('/admin')) {
    try {
      const client = await getAuth0Client();

      // Auth0 not configured — pass through; page-level guard handles redirection.
      if (!client) {
        return NextResponse.next();
      }

      const session = await client.getSession(req);

      // No session → redirect to login
      if (!session) {
        return NextResponse.redirect(new URL('/login', request.url));
      }

      // Has session but not admin → redirect to access-denied
      const role = (session.user as Record<string, unknown>)?.['https://yt-summarizer.com/role'];
      if (role !== 'admin') {
        return NextResponse.redirect(new URL('/access-denied', request.url));
      }
    } catch (err) {
      console.error('[proxy] Auth check error on admin route:', err);
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  /** Match admin routes (server-side RBAC) and Auth0 routes (SDK delegation). */
  matcher: ['/admin/:path*', '/api/auth/login', '/api/auth/logout', '/api/auth/callback'],
};
