/**
 * Hook for polling the API health endpoint and tracking service status.
 * Used for serverless DB wake-up handling (FR-020).
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { healthApi, HealthStatus } from '@/services/api';

export interface UseHealthCheckOptions {
  /** Polling interval in milliseconds (default: 5000ms) */
  pollInterval?: number;
  /** Whether to poll continuously (default: false - only polls when degraded) */
  continuous?: boolean;
  /** Whether to start polling immediately (default: true) */
  enabled?: boolean;
}

export interface UseHealthCheckResult {
  /** Current health status */
  health: HealthStatus | null;
  /** Whether the health check is currently loading */
  isLoading: boolean;
  /** Error message if health check failed */
  error: string | null;
  /** Whether the service is degraded (database waking up) */
  isDegraded: boolean;
  /** Whether the service is unhealthy */
  isUnhealthy: boolean;
  /** Whether the service is healthy */
  isHealthy: boolean;
  /** Uptime in seconds since API started */
  uptimeSeconds: number | null;
  /** Manually refresh health status */
  refresh: () => Promise<void>;
}

/**
 * Hook to poll the health endpoint and track service status.
 * Automatically increases polling frequency when service is degraded.
 */
export function useHealthCheck(options: UseHealthCheckOptions = {}): UseHealthCheckResult {
  const { pollInterval = 5000, continuous = false, enabled = true } = options;

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const mountedRef = useRef(true);

  const fetchHealth = useCallback(async () => {
    if (!enabled) return;

    try {
      setIsLoading(true);
      setError(null);
      const status = await healthApi.getHealth();

      if (mountedRef.current) {
        setHealth(status);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : 'Failed to check health');
        // Set unhealthy status when we can't reach the API
        setHealth({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          version: 'unknown',
          checks: { api: false },
          uptime_seconds: null,
          started_at: null,
        });
      }
    } finally {
      if (mountedRef.current) {
        setIsLoading(false);
      }
    }
  }, [enabled]);

  // Initial fetch and polling setup
  useEffect(() => {
    mountedRef.current = true;

    if (!enabled) {
      return;
    }

    // Initial fetch
    fetchHealth();

    // Set up polling if continuous or if we should poll when degraded
    const setupPolling = () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }

      // Poll more frequently when degraded (every 2 seconds vs normal interval)
      const interval = health?.status === 'degraded' ? 2000 : pollInterval;

      // Only poll if continuous mode is enabled or if we're degraded/unhealthy
      if (continuous || health?.status === 'degraded' || health?.status === 'unhealthy') {
        pollIntervalRef.current = setInterval(fetchHealth, interval);
      }
    };

    setupPolling();

    return () => {
      mountedRef.current = false;
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [enabled, continuous, pollInterval, health?.status, fetchHealth]);

  // Derived state
  const isDegraded = health?.status === 'degraded';
  const isUnhealthy = health?.status === 'unhealthy' || error !== null;
  const isHealthy = health?.status === 'healthy';
  const uptimeSeconds = health?.uptime_seconds ?? null;

  return {
    health,
    isLoading,
    error,
    isDegraded,
    isUnhealthy,
    isHealthy,
    uptimeSeconds,
    refresh: fetchHealth,
  };
}

export default useHealthCheck;
