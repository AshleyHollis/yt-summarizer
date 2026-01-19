/**
 * Logger Utility
 *
 * Provides structured logging with correlation IDs for tracing requests
 * across authentication flows.
 *
 * @module logger
 *
 * Implementation: T068
 */

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Log level enumeration
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Structured log context with additional metadata
 */
export interface LogContext {
  /** Correlation ID for tracing requests across services */
  correlationId?: string;

  /** User ID (if authenticated) */
  userId?: string;

  /** HTTP method (for request logs) */
  method?: string;

  /** Request path (for request logs) */
  path?: string;

  /** HTTP status code (for response logs) */
  statusCode?: number;

  /** Request duration in milliseconds */
  duration?: number;

  /** Error object (for error logs) */
  error?: Error | unknown;

  /** Additional custom fields */
  [key: string]: unknown;
}

/**
 * Logger interface
 */
export interface Logger {
  debug(message: string, context?: LogContext): void;
  info(message: string, context?: LogContext): void;
  warn(message: string, context?: LogContext): void;
  error(message: string, context?: LogContext): void;
}

// ============================================================================
// Correlation ID Generation
// ============================================================================

/**
 * Generate a unique correlation ID
 *
 * @returns A unique correlation ID (UUID v4 format)
 *
 * @remarks
 * Correlation IDs are used to trace a single request across multiple
 * services and logs. They should be:
 * - Generated once at the start of a request
 * - Passed to all downstream services
 * - Included in all log statements
 * - Returned in HTTP response headers
 *
 * @example
 * ```ts
 * const correlationId = generateCorrelationId();
 * logger.info('Request started', { correlationId });
 * // ... make API calls with correlationId header
 * logger.info('Request completed', { correlationId });
 * ```
 */
export function generateCorrelationId(): string {
  // Use crypto.randomUUID if available (modern browsers + Node.js 15+)
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback: Generate UUID v4 manually
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Extract correlation ID from HTTP headers
 *
 * @param headers - Request headers
 * @returns Correlation ID if present, undefined otherwise
 *
 * @remarks
 * Checks the following headers (in order):
 * 1. x-correlation-id
 * 2. x-request-id
 * 3. traceparent (W3C Trace Context)
 *
 * @example
 * ```ts
 * const correlationId = getCorrelationIdFromHeaders(request.headers);
 * logger.info('Request received', { correlationId });
 * ```
 */
export function getCorrelationIdFromHeaders(headers: Headers): string | undefined {
  // Try custom correlation ID header
  const customId = headers.get('x-correlation-id');
  if (customId) return customId;

  // Try x-request-id (common alternative)
  const requestId = headers.get('x-request-id');
  if (requestId) return requestId;

  // Try W3C Trace Context traceparent header
  const traceparent = headers.get('traceparent');
  if (traceparent) {
    // traceparent format: 00-<trace-id>-<parent-id>-<flags>
    const parts = traceparent.split('-');
    if (parts.length >= 2) {
      return parts[1]; // Return trace-id
    }
  }

  return undefined;
}

// ============================================================================
// Logger Implementation
// ============================================================================

/**
 * Format log message with context
 *
 * @param level - Log level
 * @param message - Log message
 * @param context - Additional context
 * @returns Formatted log string
 */
function formatLogMessage(level: LogLevel, message: string, context?: LogContext): string {
  const timestamp = new Date().toISOString();
  const levelStr = level.toUpperCase().padEnd(5);

  // Build context string
  const contextParts: string[] = [];

  if (context?.correlationId) {
    contextParts.push(`correlation_id=${context.correlationId}`);
  }

  if (context?.userId) {
    contextParts.push(`user_id=${context.userId}`);
  }

  if (context?.method && context?.path) {
    contextParts.push(`${context.method} ${context.path}`);
  }

  if (context?.statusCode) {
    contextParts.push(`status=${context.statusCode}`);
  }

  if (context?.duration !== undefined) {
    contextParts.push(`duration=${context.duration}ms`);
  }

  // Add custom fields (exclude known fields)
  if (context) {
    const knownFields = [
      'correlationId',
      'userId',
      'method',
      'path',
      'statusCode',
      'duration',
      'error',
    ];
    Object.entries(context).forEach(([key, value]) => {
      if (!knownFields.includes(key)) {
        contextParts.push(`${key}=${JSON.stringify(value)}`);
      }
    });
  }

  const contextStr = contextParts.length > 0 ? ` [${contextParts.join(', ')}]` : '';

  return `[${timestamp}] ${levelStr} ${message}${contextStr}`;
}

/**
 * Console-based logger implementation
 *
 * @remarks
 * In production, this should be replaced with a proper logging service
 * (e.g., Winston, Pino, or cloud-based logging like CloudWatch, Datadog).
 *
 * Features:
 * - Structured logging with correlation IDs
 * - Contextual metadata
 * - Color-coded output (in development)
 * - Error stack trace capture
 *
 * @example
 * ```ts
 * import { logger } from '@/lib/logger';
 *
 * // Basic logging
 * logger.info('User logged in successfully');
 *
 * // With correlation ID
 * logger.info('Auth request started', {
 *   correlationId: generateCorrelationId(),
 *   method: 'POST',
 *   path: '/api/auth/login',
 * });
 *
 * // With user context
 * logger.info('Dashboard accessed', {
 *   correlationId: req.correlationId,
 *   userId: user.sub,
 * });
 *
 * // Error logging
 * logger.error('Authentication failed', {
 *   correlationId: req.correlationId,
 *   error: err,
 *   statusCode: 401,
 * });
 * ```
 */
class ConsoleLogger implements Logger {
  debug(message: string, context?: LogContext): void {
    if (process.env.NODE_ENV === 'development') {
      const formatted = formatLogMessage('debug', message, context);
      console.debug(formatted);
      if (context?.error) {
        console.debug(context.error);
      }
    }
  }

  info(message: string, context?: LogContext): void {
    const formatted = formatLogMessage('info', message, context);
    console.info(formatted);
  }

  warn(message: string, context?: LogContext): void {
    const formatted = formatLogMessage('warn', message, context);
    console.warn(formatted);
    if (context?.error) {
      console.warn(context.error);
    }
  }

  error(message: string, context?: LogContext): void {
    const formatted = formatLogMessage('error', message, context);
    console.error(formatted);
    if (context?.error) {
      console.error(context.error);
    }
  }
}

/**
 * Default logger instance
 *
 * @remarks
 * This is a singleton logger instance. In production, consider using
 * a more sophisticated logging framework.
 */
export const logger: Logger = new ConsoleLogger();

// ============================================================================
// Request Logger Middleware Helpers
// ============================================================================

/**
 * Log request start
 *
 * @param correlationId - Correlation ID for this request
 * @param method - HTTP method
 * @param path - Request path
 *
 * @example
 * ```ts
 * const correlationId = generateCorrelationId();
 * logRequestStart(correlationId, 'POST', '/api/auth/login');
 * ```
 */
export function logRequestStart(correlationId: string, method: string, path: string): void {
  logger.info('Request started', {
    correlationId,
    method,
    path,
  });
}

/**
 * Log request completion
 *
 * @param correlationId - Correlation ID for this request
 * @param method - HTTP method
 * @param path - Request path
 * @param statusCode - HTTP status code
 * @param duration - Request duration in milliseconds
 *
 * @example
 * ```ts
 * const startTime = Date.now();
 * // ... handle request
 * const duration = Date.now() - startTime;
 * logRequestComplete(correlationId, 'POST', '/api/auth/login', 200, duration);
 * ```
 */
export function logRequestComplete(
  correlationId: string,
  method: string,
  path: string,
  statusCode: number,
  duration: number
): void {
  const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';
  logger[level]('Request completed', {
    correlationId,
    method,
    path,
    statusCode,
    duration,
  });
}

/**
 * Log request error
 *
 * @param correlationId - Correlation ID for this request
 * @param method - HTTP method
 * @param path - Request path
 * @param error - Error object
 *
 * @example
 * ```ts
 * try {
 *   // ... handle request
 * } catch (error) {
 *   logRequestError(correlationId, 'POST', '/api/auth/login', error);
 *   throw error;
 * }
 * ```
 */
export function logRequestError(
  correlationId: string,
  method: string,
  path: string,
  error: unknown
): void {
  logger.error('Request failed', {
    correlationId,
    method,
    path,
    error,
  });
}

// ============================================================================
// Auth-Specific Logging Helpers
// ============================================================================

/**
 * Log authentication event
 *
 * @param event - Event type (e.g., 'login', 'logout', 'session_refresh')
 * @param context - Event context
 *
 * @example
 * ```ts
 * logAuthEvent('login', {
 *   correlationId,
 *   userId: user.sub,
 *   provider: 'google-oauth2',
 * });
 * ```
 */
export function logAuthEvent(event: string, context: LogContext): void {
  logger.info(`Auth: ${event}`, context);
}

/**
 * Log authorization check
 *
 * @param resource - Resource being accessed
 * @param allowed - Whether access was allowed
 * @param context - Check context
 *
 * @example
 * ```ts
 * logAuthzCheck('/admin', hasRole('admin'), {
 *   correlationId,
 *   userId: user.sub,
 *   role: user['https://yt-summarizer.com/role'],
 * });
 * ```
 */
export function logAuthzCheck(resource: string, allowed: boolean, context: LogContext): void {
  const message = `Authorization ${allowed ? 'granted' : 'denied'}: ${resource}`;
  logger[allowed ? 'info' : 'warn'](message, context);
}

/**
 * Default export
 */
export default logger;
