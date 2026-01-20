// Direct import from dist path as workaround for Turbopack Edge runtime subpath export resolution
// See: https://github.com/vercel/next.js/issues/XXXXX
import { Auth0Client } from '@auth0/nextjs-auth0/dist/server/index.js';

/**
 * Auth0 client instance for server-side authentication.
 * Configuration is automatically loaded from environment variables:
 * - AUTH0_DOMAIN
 * - AUTH0_CLIENT_ID
 * - AUTH0_CLIENT_SECRET
 * - AUTH0_SECRET (session encryption key)
 * - APP_BASE_URL (application base URL)
 */
export const auth0 = new Auth0Client({
  // All configuration is read from environment variables
  // See .github/workflows/swa-baseline-deploy.yml for variable definitions
});
