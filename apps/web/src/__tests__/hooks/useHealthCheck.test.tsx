/**
 * Tests for useHealthCheck hook.
 * Verifies health polling, status detection, and retry logic.
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useHealthCheck } from '@/hooks/useHealthCheck';
import { healthApi, HealthStatus } from '@/services/api';

// Mock the healthApi
vi.mock('@/services/api', () => ({
  healthApi: {
    getHealth: vi.fn(),
  },
}));

describe('useHealthCheck', () => {
  const mockHealthyResponse: HealthStatus = {
    status: 'healthy',
    timestamp: '2026-01-06T12:00:00Z',
    version: '1.0.0',
    checks: { api: true, database: true },
    uptime_seconds: 3600,
    started_at: '2026-01-06T11:00:00Z',
  };

  const mockDegradedResponse: HealthStatus = {
    status: 'degraded',
    timestamp: '2026-01-06T12:00:00Z',
    version: '1.0.0',
    checks: { api: true, database: false },
    uptime_seconds: 10,
    started_at: '2026-01-06T11:59:50Z',
  };

  const mockUnhealthyResponse: HealthStatus = {
    status: 'unhealthy',
    timestamp: '2026-01-06T12:00:00Z',
    version: '1.0.0',
    checks: { api: false },
    uptime_seconds: null,
    started_at: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should fetch health status on mount', async () => {
    vi.mocked(healthApi).getHealth.mockResolvedValue(mockHealthyResponse);

    const { result } = renderHook(() => useHealthCheck({ enabled: true }));

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(vi.mocked(healthApi).getHealth).toHaveBeenCalled();
    expect(result.current.health).toEqual(mockHealthyResponse);
    expect(result.current.isHealthy).toBe(true);
    expect(result.current.isDegraded).toBe(false);
    expect(result.current.isUnhealthy).toBe(false);
  });

  it('should detect degraded status correctly', async () => {
    vi.mocked(healthApi).getHealth.mockResolvedValue(mockDegradedResponse);

    const { result } = renderHook(() => useHealthCheck({ enabled: true }));

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.isDegraded).toBe(true);
    expect(result.current.isHealthy).toBe(false);
    expect(result.current.health?.status).toBe('degraded');
  });

  it('should detect unhealthy status when API call fails', async () => {
    vi.mocked(healthApi).getHealth.mockRejectedValue(new Error('Network error'));

    const { result } = renderHook(() => useHealthCheck({ enabled: true }));

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.isUnhealthy).toBe(true);
    expect(result.current.error).toBe('Network error');
    expect(result.current.health?.status).toBe('unhealthy');
  });

  it('should return uptime from health response', async () => {
    vi.mocked(healthApi).getHealth.mockResolvedValue(mockHealthyResponse);

    const { result } = renderHook(() => useHealthCheck({ enabled: true }));

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.uptimeSeconds).toBe(3600);
  });

  it('should not fetch when disabled', async () => {
    const { result } = renderHook(() => useHealthCheck({ enabled: false }));

    // Wait a bit to ensure no fetch happens
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(vi.mocked(healthApi).getHealth).not.toHaveBeenCalled();
    expect(result.current.health).toBeNull();
  });

  it('should allow manual refresh', async () => {
    // Start with degraded, but make it return healthy on refresh
    let returnHealthy = false;
    vi.mocked(healthApi).getHealth.mockImplementation(async () => {
      if (returnHealthy) {
        return mockHealthyResponse;
      }
      return mockDegradedResponse;
    });

    const { result } = renderHook(() => useHealthCheck({ enabled: true }));

    await waitFor(() => {
      expect(result.current.health).not.toBeNull();
    });

    // Now switch to healthy and trigger refresh
    returnHealthy = true;

    await act(async () => {
      await result.current.refresh();
    });

    await waitFor(() => {
      expect(result.current.isHealthy).toBe(true);
    });

    // Should have called at least twice (initial + refresh)
    expect(vi.mocked(healthApi).getHealth.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it('should poll more frequently when degraded', async () => {
    vi.useFakeTimers();

    vi.mocked(healthApi).getHealth.mockResolvedValue(mockDegradedResponse);

    renderHook(() => useHealthCheck({ enabled: true, pollInterval: 5000 }));

    // Initial fetch
    await act(async () => {
      await vi.runOnlyPendingTimersAsync();
    });

    const initialCallCount = vi.mocked(healthApi).getHealth.mock.calls.length;
    expect(initialCallCount).toBeGreaterThanOrEqual(1);

    // Should poll at 2s interval when degraded
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });

    // Should have polled again
    expect(vi.mocked(healthApi).getHealth.mock.calls.length).toBeGreaterThan(initialCallCount);

    vi.useRealTimers();
  });
});
