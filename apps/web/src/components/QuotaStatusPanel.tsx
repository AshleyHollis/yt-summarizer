/**
 * QuotaStatusPanel Component
 *
 * Shows current quota usage and queue status.
 * Includes "Request Expedite" button when videos are queued.
 */

'use client';

import React, { useState } from 'react';
import { useQuota } from '@/hooks/useQuota';
import { useAuth } from '@/hooks/useAuth';
import { quotaApi } from '@/services/api';

export function QuotaStatusPanel() {
  const { isAuthenticated } = useAuth();
  const { quota, isLoading } = useQuota();
  const [expediteReason, setExpediteReason] = useState('');
  const [showExpediteModal, setShowExpediteModal] = useState(false);
  const [expediteStatus, setExpediteStatus] = useState<string | null>(null);

  if (!isAuthenticated || isLoading || !quota) return null;
  if (quota.tier === 'admin') return null; // Admins have no limits

  const handleRequestExpedite = async () => {
    try {
      await quotaApi.requestExpedite(expediteReason || undefined);
      setExpediteStatus('Expedite request submitted — pending admin approval');
      setShowExpediteModal(false);
      setExpediteReason('');
    } catch {
      setExpediteStatus('Failed to submit expedite request');
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700/50 p-4 space-y-3">
      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
        Quota Status
      </h3>

      {/* Video quota */}
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-600 dark:text-gray-400">Videos today</span>
        <span className="font-medium">
          {quota.videos.processed_today}/{quota.videos.limit ?? '∞'}
          {quota.videos.remaining !== null && quota.videos.remaining > 0 && (
            <span className="text-green-600 dark:text-green-400 ml-1">
              ({quota.videos.remaining} remaining)
            </span>
          )}
        </span>
      </div>

      {/* Queued videos */}
      {quota.videos.queued > 0 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">
            🔵 Queued videos
          </span>
          <span className="font-medium text-blue-600 dark:text-blue-400">
            {quota.videos.queued}
            {quota.videos.estimated_days && (
              <span className="text-gray-500 ml-1">
                (~{quota.videos.estimated_days}d)
              </span>
            )}
          </span>
        </div>
      )}

      {/* Copilot quota */}
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-600 dark:text-gray-400">Chat queries/hr</span>
        <span className="font-medium">
          {quota.copilot.used_this_hour}/{quota.copilot.limit ?? '∞'}
        </span>
      </div>

      {/* Expedite request */}
      {quota.videos.queued > 0 && !expediteStatus && (
        <button
          onClick={() => setShowExpediteModal(true)}
          className="w-full text-sm py-2 px-3 bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800 rounded-lg hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors"
        >
          ⚡ Request Expedite Processing
        </button>
      )}

      {expediteStatus && (
        <p className="text-xs text-amber-600 dark:text-amber-400">{expediteStatus}</p>
      )}

      {/* Expedite modal */}
      {showExpediteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Request Expedite Processing
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              You have {quota.videos.queued} videos in the queue. An admin can approve
              immediate processing of all queued videos.
            </p>
            <textarea
              value={expediteReason}
              onChange={(e) => setExpediteReason(e.target.value)}
              placeholder="Optional: explain why you need expedited processing"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm dark:bg-gray-700 dark:text-white resize-none"
              rows={3}
            />
            <div className="flex gap-3">
              <button
                onClick={handleRequestExpedite}
                className="flex-1 py-2 bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors text-sm font-medium"
              >
                Submit Request
              </button>
              <button
                onClick={() => setShowExpediteModal(false)}
                className="flex-1 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
