/**
 * Next.js Middleware entry point.
 *
 * Re-exports the proxy handler and route matcher from proxy.ts.
 * Next.js requires this file to be named `middleware.ts` and export
 * a function named `middleware`.
 *
 * @see apps/web/src/proxy.ts for the implementation
 */

export { proxy as middleware, config } from './proxy';
