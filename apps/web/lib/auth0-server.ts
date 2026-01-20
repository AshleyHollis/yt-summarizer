// Re-export wrapper to work around Turbopack subpath export resolution issues
// See: https://github.com/vercel/next.js/issues/...
//
// Turbopack has issues resolving package.json "exports" subpaths in Edge/Middleware runtime
// This file acts as a bridge to properly import from the Auth0 package

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - Turbopack bundling workaround
export { Auth0Client } from '@auth0/nextjs-auth0/dist/server/client.js';
