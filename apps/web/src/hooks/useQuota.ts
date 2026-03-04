/**
 * useQuota Hook
 *
 * Fetches and provides quota status for the authenticated user.
 * Polls periodically to keep data fresh.
 */

'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from './useAuth';
import { quotaApi, type QuotaStatus } from '@/services/api';

interface UseQuotaReturn {
  quota: QuotaStatus | null;
  isLoading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

export function useQuota(pollIntervalMs = 60000): UseQuotaReturn {
  const { isAuthenticated } = useAuth();
  const [quota, setQuota] = useState<QuotaStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!isAuthenticated) return;
    setIsLoading(true);
    try {
      const status = await quotaApi.getStatus();
      setQuota(status);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch quota');
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    refresh();
    if (!isAuthenticated || !pollIntervalMs) return;
    const interval = setInterval(refresh, pollIntervalMs);
    return () => clearInterval(interval);
  }, [refresh, isAuthenticated, pollIntervalMs]);

  return { quota, isLoading, error, refresh };
}
