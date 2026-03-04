/**
 * CopilotQuotaIndicator
 *
 * Shows remaining copilot queries in a compact bar below the chat.
 */

'use client';

import { useQuota } from '@/hooks/useQuota';
import { useAuth } from '@/hooks/useAuth';

export function CopilotQuotaIndicator() {
  const { isAuthenticated } = useAuth();
  const { quota } = useQuota(30000); // Poll every 30s

  if (!isAuthenticated || !quota || quota.tier === 'admin') return null;

  const { used_this_hour, limit, resets_in_seconds } = quota.copilot;
  if (!limit) return null;

  const remaining = limit - used_this_hour;
  const pct = Math.round((used_this_hour / limit) * 100);
  const isLow = remaining <= 5;
  const isExhausted = remaining <= 0;

  const resetMin = Math.ceil(resets_in_seconds / 60);

  return (
    <div className="px-3 py-1.5 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 text-xs">
      <div className="flex items-center justify-between">
        <span className={isExhausted ? 'text-red-500' : isLow ? 'text-amber-500' : 'text-gray-500 dark:text-gray-400'}>
          {isExhausted
            ? `Quota resets in ${resetMin}m`
            : `${remaining}/${limit} queries remaining`}
        </span>
        {/* Mini progress bar */}
        <div className="w-16 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden ml-2">
          <div
            className={`h-full rounded-full transition-all ${
              isExhausted ? 'bg-red-500' : isLow ? 'bg-amber-500' : 'bg-green-500'
            }`}
            style={{ width: `${Math.min(pct, 100)}%` }}
          />
        </div>
      </div>
    </div>
  );
}
