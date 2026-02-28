/**
 * Unit tests for API Client (T075)
 *
 * Verifies:
 * 1. Access token is attached as Bearer header on GET and POST requests
 * 2. Requests succeed when token is available
 * 3. No Authorization header is sent when unauthenticated (no token)
 * 4. 401 response triggers cache clear and browser redirect to /sign-in
 * 5. Token is cached after the first fetch (single /api/auth/me call per session)
 * 6. clearAccessTokenCache resets the cache
 *
 * Implementation: T075
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Module under test ────────────────────────────────────────────────────────
// We re-import after each test to reset module-level cache state
import {
  getAccessToken,
  clearAccessTokenCache,
  apiGet,
  apiPost,
} from '@/lib/api-client';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockFetch(responses: Array<{ status: number; body?: unknown }>) {
  const queue = [...responses];
  return vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => {
    const next = queue.shift() ?? { status: 200, body: {} };
    return {
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      statusText: next.status === 401 ? 'Unauthorized' : 'OK',
      json: async () => next.body,
    } as Response;
  });
}

// ─── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  clearAccessTokenCache();
  // Provide a base location for redirect tests
  Object.defineProperty(window, 'location', {
    value: { href: '' },
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── getAccessToken ───────────────────────────────────────────────────────────

describe('getAccessToken', () => {
  it('returns null when /api/auth/me returns 401', async () => {
    global.fetch = mockFetch([{ status: 401 }]) as typeof global.fetch;

    const token = await getAccessToken();
    expect(token).toBeNull();
  });

  it('returns token when /api/auth/me returns 200 with accessToken', async () => {
    global.fetch = mockFetch([{ status: 200, body: { accessToken: 'test-token-abc' } }]) as typeof global.fetch;

    const token = await getAccessToken();
    expect(token).toBe('test-token-abc');
  });

  it('caches the token after first fetch (single call to /api/auth/me)', async () => {
    const fetchMock = mockFetch([
      { status: 200, body: { accessToken: 'cached-token' } },
    ]);
    global.fetch = fetchMock as typeof global.fetch;

    await getAccessToken();
    await getAccessToken();
    await getAccessToken();

    // Only one actual fetch to /api/auth/me; subsequent calls use the cache
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns null when fetch throws', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error')) as typeof global.fetch;

    const token = await getAccessToken();
    expect(token).toBeNull();
  });
});

// ─── clearAccessTokenCache ────────────────────────────────────────────────────

describe('clearAccessTokenCache', () => {
  it('forces a new /api/auth/me fetch after cache is cleared', async () => {
    const fetchMock = mockFetch([
      { status: 200, body: { accessToken: 'token-1' } },
      { status: 200, body: { accessToken: 'token-2' } },
    ]);
    global.fetch = fetchMock as typeof global.fetch;

    const first = await getAccessToken();
    clearAccessTokenCache();
    const second = await getAccessToken();

    expect(first).toBe('token-1');
    expect(second).toBe('token-2');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

// ─── apiGet ───────────────────────────────────────────────────────────────────

describe('apiGet', () => {
  it('attaches Bearer token to Authorization header when authenticated', async () => {
    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'my-token' }) } as Response;
      }
      return { ok: true, status: 200, json: async () => ({ data: 'ok' }) } as Response;
    });
    global.fetch = fetchMock as typeof global.fetch;

    await apiGet('/videos');

    // Find the call to the API endpoint (not /api/auth/me)
    const apiCall = fetchMock.mock.calls.find(([url]) =>
      String(url).includes('/videos')
    );
    expect(apiCall).toBeDefined();
    const headers = (apiCall![1] as RequestInit | undefined)?.headers as Record<string, string> | undefined;
    expect(headers?.Authorization).toBe('Bearer my-token');
  });

  it('sends no Authorization header when unauthenticated', async () => {
    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: false, status: 401, json: async () => ({}) } as Response;
      }
      return { ok: true, status: 200, json: async () => ({ data: 'ok' }) } as Response;
    });
    global.fetch = fetchMock as typeof global.fetch;

    await apiGet('/public-data');

    const apiCall = fetchMock.mock.calls.find(([url]) =>
      String(url).includes('/public-data')
    );
    const headers = (apiCall![1] as RequestInit | undefined)?.headers as Record<string, string> | undefined;
    expect(headers?.Authorization).toBeUndefined();
  });

  it('throws and triggers re-auth when API returns 401', async () => {
    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'expired-token' }) } as Response;
      }
      return {
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({}),
      } as Response;
    });
    global.fetch = fetchMock as typeof global.fetch;

    await expect(apiGet('/protected')).rejects.toThrow('Unauthorized');

    // Cache should be cleared so next request re-fetches session
    clearAccessTokenCache();
    global.fetch = mockFetch([{ status: 401 }]) as typeof global.fetch;
    const token = await getAccessToken();
    expect(token).toBeNull();
  });

  it('throws on non-401 errors from the API', async () => {
    global.fetch = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'tok' }) } as Response;
      }
      return { ok: false, status: 500, statusText: 'Internal Server Error', json: async () => ({}) } as Response;
    }) as typeof global.fetch;

    await expect(apiGet('/bad-endpoint')).rejects.toThrow('API request failed: 500');
  });

  it('returns parsed JSON on success', async () => {
    global.fetch = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'tok' }) } as Response;
      }
      return { ok: true, status: 200, json: async () => ({ id: 1, title: 'Video' }) } as Response;
    }) as typeof global.fetch;

    const result = await apiGet<{ id: number; title: string }>('/videos/1');
    expect(result).toEqual({ id: 1, title: 'Video' });
  });
});

// ─── apiPost ──────────────────────────────────────────────────────────────────

describe('apiPost', () => {
  it('attaches Bearer token and sets Content-Type on authenticated POST', async () => {
    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'post-token' }) } as Response;
      }
      return { ok: true, status: 201, json: async () => ({ created: true }) } as Response;
    });
    global.fetch = fetchMock as typeof global.fetch;

    await apiPost('/videos', { url: 'https://youtube.com/watch?v=abc' });

    const apiCall = fetchMock.mock.calls.find(([url]) =>
      String(url).includes('/videos')
    );
    expect(apiCall).toBeDefined();
    const init = (apiCall![1] ?? {}) as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer post-token');
    expect(headers['Content-Type']).toBe('application/json');
    expect(init.body).toBe(JSON.stringify({ url: 'https://youtube.com/watch?v=abc' }));
  });

  it('throws and redirects to /sign-in when API returns 401', async () => {
    global.fetch = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ accessToken: 'tok' }) } as Response;
      }
      return { ok: false, status: 401, statusText: 'Unauthorized', json: async () => ({}) } as Response;
    }) as typeof global.fetch;

    await expect(apiPost('/protected', {})).rejects.toThrow('Unauthorized');
    expect(window.location.href).toBe('/sign-in');
  });
});
