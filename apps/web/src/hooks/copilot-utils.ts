/**
 * Utility functions for Copilot actions.
 */

/**
 * Format seconds as MM:SS or HH:MM:SS
 */
export function formatTime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  }
  return `${m}:${s.toString().padStart(2, '0')}`;
}

/**
 * API base URL from environment
 */
export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
  const response = await fetch(`${API_URL}${path}`, {
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
