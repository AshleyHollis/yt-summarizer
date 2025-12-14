/**
 * Correlation ID generator and utilities for request tracing.
 *
 * Correlation IDs are used to trace requests across frontend and backend services.
 * They are passed in the X-Correlation-ID header for all API requests.
 */

/**
 * Generate a new correlation ID (UUID v4 format)
 */
export function generateCorrelationId(): string {
  // Use crypto.randomUUID if available (modern browsers and Node.js 19+)
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback for older environments
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Storage key for persisting correlation ID across page loads
 */
const SESSION_CORRELATION_KEY = 'yt-summarizer-session-id';

/**
 * Get or create a session-level correlation ID.
 * This ID persists for the browser session and can be used to correlate
 * all requests from a single user session.
 */
export function getSessionCorrelationId(): string {
  if (typeof window === 'undefined') {
    // Server-side rendering - generate a new ID each time
    return generateCorrelationId();
  }

  let sessionId = sessionStorage.getItem(SESSION_CORRELATION_KEY);
  if (!sessionId) {
    sessionId = generateCorrelationId();
    sessionStorage.setItem(SESSION_CORRELATION_KEY, sessionId);
  }

  return sessionId;
}

/**
 * Correlation context for passing IDs through component trees
 */
export interface CorrelationContext {
  /** Current request correlation ID */
  correlationId: string;
  /** Session-level correlation ID */
  sessionId: string;
}

/**
 * Create a new correlation context for a request
 */
export function createCorrelationContext(): CorrelationContext {
  return {
    correlationId: generateCorrelationId(),
    sessionId: getSessionCorrelationId(),
  };
}

/**
 * Format correlation ID for logging
 */
export function formatCorrelationId(id: string): string {
  return `[${id.substring(0, 8)}]`;
}
