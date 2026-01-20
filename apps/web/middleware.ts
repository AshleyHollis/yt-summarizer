/**
 * Next.js Middleware Entry Point
 *
 * This file is automatically detected by Next.js and runs on matching routes.
 * It delegates to the proxy function for authentication and authorization.
 */

import { proxy, config as proxyConfig } from './src/proxy';

// Export the proxy function as middleware
export const middleware = proxy;

// Re-export the config from proxy
export const config = proxyConfig;
