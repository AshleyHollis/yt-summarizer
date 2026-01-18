/**
 * Auth0 SDK Client
 * 
 * This creates the Auth0 SDK client instance for server-side authentication.
 * The client is used across the application for auth operations.
 * 
 * @module auth0-client
 */

import { Auth0Client } from '@auth0/nextjs-auth0/server';

/**
 * Auth0 client instance
 * 
 * Automatically configured from environment variables:
 * - AUTH0_SECRET
 * - AUTH0_ISSUER_BASE_URL
 * - AUTH0_CLIENT_ID
 * - AUTH0_CLIENT_SECRET
 * - AUTH0_BASE_URL
 */
export const auth0 = new Auth0Client();
