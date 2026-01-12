/**
 * Health Status Context - shares health state across the app.
 * Used for serverless DB wake-up handling (FR-020).
 */

'use client';

import React, { createContext, useContext, ReactNode, ReactElement } from 'react';
import { useHealthCheck, UseHealthCheckResult } from '@/hooks/useHealthCheck';

// Context type is the same as the hook result
type HealthStatusContextType = UseHealthCheckResult;

const HealthStatusContext = createContext<HealthStatusContextType | null>(null);

export interface HealthStatusProviderProps {
  children: ReactNode;
  /** Polling interval in milliseconds (default: 5000ms) */
  pollInterval?: number;
}

/**
 * Provider component that wraps the app and shares health status.
 * Health is polled automatically and more frequently when degraded.
 */
export function HealthStatusProvider({
  children,
  pollInterval = 5000,
}: HealthStatusProviderProps): ReactElement {
  const healthState = useHealthCheck({
    pollInterval,
    continuous: false, // Only poll when degraded
    enabled: true,
  });

  return (
    <HealthStatusContext.Provider value={healthState}>
      {children}
    </HealthStatusContext.Provider>
  );
}

/**
 * Hook to access health status from context.
 * Must be used within a HealthStatusProvider.
 */
export function useHealthStatus(): HealthStatusContextType {
  const context = useContext(HealthStatusContext);

  if (!context) {
    throw new Error('useHealthStatus must be used within a HealthStatusProvider');
  }

  return context;
}

export default HealthStatusContext;
