/**
 * API Client — Auth-aware HTTP client for the YT Summarizer backend API.
 *
 * Reads the Auth0 session access token from /api/auth/me and attaches it as a
 * Bearer token to outgoing API requests. Handles 401 responses by redirecting
 * the user to the login page so the session can be refreshed.
 *
 * FR-017: System MUST sync user authentication state between UI and API layers.
 *
 * @module api-client
 */

/** Base URL of the backend API (injected at build time via next.config.ts env). */
const API_BASE_URL =
  typeof window !== 'undefined'
    ? (process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000')
    : (process.env.API_URL ?? 'http://localhost:8000');

/** Cached access token to avoid fetching on every request within the same session. */
let _cachedAccessToken: string | null = null;

/**
 * Retrieve the current session access token from the server-side /api/auth/me endpoint.
 *
 * Returns null when Auth0 is not configured or the user is unauthenticated.
 */
export async function getAccessToken(): Promise<string | null> {
  if (_cachedAccessToken) return _cachedAccessToken;

  try {
    const res = await fetch('/api/auth/me', { credentials: 'include' });
    if (!res.ok) return null;

    const data = (await res.json()) as { accessToken?: string };
    _cachedAccessToken = data.accessToken ?? null;
    return _cachedAccessToken;
  } catch {
    return null;
  }
}

/** Clear the token cache (call after logout or 401). */
export function clearAccessTokenCache(): void {
  _cachedAccessToken = null;
}

/**
 * Build the Authorization header if a token is available.
 *
 * @internal
 */
async function authHeader(): Promise<Record<string, string>> {
  const token = await getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Handle a 401 response from the API by clearing the token cache and
 * optionally redirecting the browser to /sign-in for re-authentication.
 *
 * @internal
 */
function handleUnauthorized(): void {
  clearAccessTokenCache();
  // Only redirect in the browser
  if (typeof window !== 'undefined') {
    window.location.href = '/sign-in';
  }
}

/**
 * Make an authenticated GET request to the backend API.
 *
 * @param path - API path (e.g. `/videos`)
 * @param init - Additional fetch options
 * @returns The parsed JSON response
 * @throws On non-2xx responses (after handling 401)
 *
 * @example
 * ```ts
 * const videos = await apiGet<Video[]>('/videos');
 * ```
 */
export async function apiGet<T = unknown>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers = await authHeader();
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'GET',
    headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
    credentials: 'include',
  });

  if (res.status === 401) {
    handleUnauthorized();
    throw new Error('Unauthorized: session expired');
  }

  if (!res.ok) {
    throw new Error(`API request failed: ${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<T>;
}

/**
 * Make an authenticated POST request to the backend API.
 *
 * @param path - API path (e.g. `/videos`)
 * @param body - Request body (will be JSON-serialized)
 * @param init - Additional fetch options
 * @returns The parsed JSON response
 */
export async function apiPost<T = unknown>(
  path: string,
  body?: unknown,
  init?: RequestInit
): Promise<T> {
  const headers = await authHeader();
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
      ...(init?.headers as Record<string, string> | undefined),
    },
    credentials: 'include',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    handleUnauthorized();
    throw new Error('Unauthorized: session expired');
  }

  if (!res.ok) {
    throw new Error(`API request failed: ${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<T>;
}
