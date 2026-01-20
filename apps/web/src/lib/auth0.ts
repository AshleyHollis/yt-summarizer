/**
 * Auth0 SDK Client
 *
 * This creates the Auth0 SDK client instance for server-side authentication.
 * The client is used across the application for auth operations.
 *
 * IMPORTANT: This uses lazy initialization with graceful degradation.
 * If Auth0 environment variables are missing or invalid, the app will still start,
 * but authentication features will be disabled.
 *
 * CRITICAL: We use dynamic imports to avoid loading the Auth0 SDK at module load time.
 * This prevents SWA warmup timeouts because the SDK is only loaded when actually needed.
 *
 * @module auth0-client
 */

// Type import only - doesn't execute any code at runtime
import type { Auth0Client } from '@auth0/nextjs-auth0/server';

/**
 * Checks if Auth0 environment variables are properly configured
 */
export function isAuth0Configured(): boolean {
  const required = [
    'AUTH0_SECRET',
    'AUTH0_ISSUER_BASE_URL',
    'AUTH0_CLIENT_ID',
    'AUTH0_CLIENT_SECRET',
  ];

  return required.every((key) => {
    const value = process.env[key];
    return value && value.trim().length > 0;
  });
}

/**
 * Auth0 client instance (lazy-initialized)
 *
 * Automatically configured from environment variables:
 * - AUTH0_SECRET
 * - AUTH0_ISSUER_BASE_URL
 * - AUTH0_CLIENT_ID
 * - AUTH0_CLIENT_SECRET
 * - AUTH0_BASE_URL (optional, inferred from request if not set)
 *
 * If configuration is invalid, returns null and logs a warning.
 */
let _auth0Client: Auth0Client | null = null;
let _initializationAttempted = false;
let _initializationError: Error | null = null;

/**
 * Get the Auth0 client instance (async, uses dynamic import)
 *
 * CRITICAL: This function is async because it uses dynamic imports to
 * avoid loading the Auth0 SDK at module initialization time. This is
 * necessary to prevent Azure SWA warmup timeouts.
 */
export async function getAuth0Client(): Promise<Auth0Client | null> {
  // Return cached client if already initialized
  if (_initializationAttempted) {
    return _auth0Client;
  }

  _initializationAttempted = true;

  try {
    // Check if configuration is present BEFORE loading the SDK
    if (!isAuth0Configured()) {
      const missingVars = [
        'AUTH0_SECRET',
        'AUTH0_ISSUER_BASE_URL',
        'AUTH0_CLIENT_ID',
        'AUTH0_CLIENT_SECRET',
      ].filter((key) => !process.env[key]);

      _initializationError = new Error(`Auth0 configuration missing: ${missingVars.join(', ')}`);

      console.warn(
        '[Auth0] Authentication is DISABLED - missing required environment variables:',
        missingVars.join(', ')
      );
      console.warn('[Auth0] The application will start, but auth features will not work.');

      return null;
    }

    // Only load the SDK when we know configuration is present
    // This is the key fix - dynamic import prevents loading at module init time
    const { Auth0Client: Auth0ClientClass } = await import('@auth0/nextjs-auth0/server');

    // Attempt to create client
    _auth0Client = new Auth0ClientClass();
    console.log('[Auth0] Authentication is ENABLED');
    return _auth0Client;
  } catch (error) {
    _initializationError = error as Error;
    console.error('[Auth0] Failed to initialize Auth0 client:', error);
    console.warn('[Auth0] The application will start, but auth features will not work.');
    return null;
  }
}

/**
 * Get the initialization error (if any)
 */
export function getAuth0Error(): Error | null {
  return _initializationError;
}
