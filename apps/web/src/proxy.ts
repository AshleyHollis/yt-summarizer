/**
 * Next.js 16 Proxy - TEMPORARILY BYPASSED FOR SWA WARMUP DEBUGGING
 *
 * This proxy is completely bypassed to test if it's causing the SWA warmup timeout.
 * If deployment succeeds with this bypass, the proxy code is the culprit.
 *
 * TODO: Re-enable after fixing SWA warmup timeout issue
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 */

import { NextResponse } from 'next/server';

/**
 * BYPASS PROXY - Immediately pass through all requests
 *
 * This is a diagnostic change to isolate the SWA warmup timeout issue.
 * If deployment succeeds, the Auth0/middleware code is causing the problem.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function proxy(request: Request) {
  // BYPASS: Do nothing, just pass through
  return NextResponse.next();
}

/**
 * EMPTY MATCHER - Proxy runs on nothing (completely disabled)
 *
 * This is a diagnostic change. If SWA deployment succeeds with empty matcher,
 * then the proxy code execution is definitely the culprit.
 */
export const config = {
  matcher: [],
};
