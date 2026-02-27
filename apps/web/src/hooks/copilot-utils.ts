/**
 * Utility functions for Copilot actions.
 */

import { formatDuration } from '@/utils/formatDuration';
import { getClientApiUrl } from '@/services/runtimeConfig';

// Re-export formatDuration as formatTime for backward compatibility
export const formatTime = formatDuration;

/**
 * Default minimum relevance threshold for filtering results
 */
export const MIN_RELEVANCE_THRESHOLD = 0.50;

/**
 * Make an API call with error handling
 */
export async function apiCall<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const apiUrl = getClientApiUrl();
  const response = await fetch(`${apiUrl}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`API call failed: ${response.statusText}`);
  }

  return response.json();
}

/**
 * POST request helper
 */
export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiCall<T>(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * GET request helper
 */
export async function apiGet<T>(path: string): Promise<T> {
  return apiCall<T>(path, { method: "GET" });
}
