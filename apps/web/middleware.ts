/**
 * Next.js Middleware Entry Point
 *
 * This file is automatically detected by Next.js and runs on matching routes.
 * It delegates to the proxy function for authentication and authorization.
 */

import { proxy } from './src/proxy';

// Export the proxy function as middleware
export const middleware = proxy;

// Config must be a static object (cannot re-export from proxy)
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
