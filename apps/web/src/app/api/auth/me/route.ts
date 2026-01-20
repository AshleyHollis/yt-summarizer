/**
 * Auth0 Session Endpoint
 *
 * Returns the current user's session information.
 * This endpoint is called by AuthProvider to check authentication status.
 *
 * @returns 200 with user data if authenticated, 401 if not authenticated
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuth0Client } from '@/lib/auth0';

/**
 * GET /api/auth/me
 *
 * Returns the current user session using Auth0 SDK.
 * Handles graceful degradation when Auth0 is not configured.
 */
export async function GET(req: NextRequest) {
  try {
    const client = getAuth0Client();

    // If Auth0 is not configured, return 401 immediately
    if (!client) {
      return NextResponse.json({ error: 'Authentication not configured' }, { status: 401 });
    }

    // Get the session using Auth0 SDK
    const session = await client.getSession(req);

    // If no session exists, return 401
    if (!session) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Return the user data from the session
    return NextResponse.json({
      user: session.user,
      accessToken: session.accessToken,
      // Note: We don't expose refreshToken to the client for security
    });
  } catch (error) {
    console.error('[/api/auth/me] Error retrieving session:', error);

    // Return 401 for auth errors (invalid token, expired session, etc.)
    return NextResponse.json({ error: 'Authentication error' }, { status: 401 });
  }
}
