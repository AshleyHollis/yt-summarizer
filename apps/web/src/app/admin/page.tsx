/**
 * Admin Dashboard Page
 *
 * This page is protected by middleware and only accessible to users with the 'admin' role.
 * It provides administrative functions for managing the YouTube Summarizer application.
 *
 * Protection:
 * - Middleware checks authentication and admin role
 * - Unauthenticated users → Redirected to /sign-in
 * - Non-admin users → Redirected to /forbidden
 *
 * Features:
 * - User management overview
 * - System statistics
 * - Application settings
 * - Video processing monitoring
 */

'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../hooks/useAuth';
import { adminQuotaApi, type ExpediteRequest } from '@/services/api';

export default function AdminDashboard() {
  const { user, isLoading, isAuthenticated, hasRole } = useAuth();
  const router = useRouter();

  // Client-side auth guard — defense in depth alongside the proxy layer.
  // Redirects if the proxy did not (e.g. Auth0 not configured in dev, or direct fetch).
  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.replace('/sign-in');
    } else if (!hasRole('admin')) {
      router.replace('/forbidden');
    }
  }, [isLoading, isAuthenticated, hasRole, router]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-[#0f0f0f]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        <span className="ml-3 text-lg text-gray-900 dark:text-white">
          Loading admin dashboard...
        </span>
      </div>
    );
  }

  // Render nothing while redirect is in flight (prevents content flash)
  if (!isAuthenticated || !hasRole('admin')) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:bg-[#0f0f0f] dark:from-transparent dark:via-transparent dark:to-transparent">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">Admin Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Welcome, {user?.email || 'Administrator'}
          </p>
          {user?.['https://yt-summarizer.com/role'] && (
            <span className="inline-block mt-2 px-3 py-1 text-sm font-semibold text-white bg-purple-600 rounded-full">
              {user['https://yt-summarizer.com/role'].toUpperCase()}
            </span>
          )}
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Users"
            value="--"
            description="Registered users"
            icon="👥"
            color="blue"
          />
          <StatCard
            title="Videos Processed"
            value="--"
            description="All time"
            icon="🎥"
            color="green"
          />
          <StatCard
            title="Active Sessions"
            value="--"
            description="Currently online"
            icon="🔄"
            color="yellow"
          />
          <StatCard
            title="System Health"
            value="Good"
            description="All services operational"
            icon="✅"
            color="purple"
          />
        </div>

        {/* Admin Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Expedite Requests - Quota Management */}
          <div className="lg:col-span-2">
            <ExpediteRequestsPanel />
          </div>

          {/* User Management */}
          <AdminSection
            title="User Management"
            description="Manage user accounts, roles, and permissions"
            icon="👥"
            actions={[
              { label: 'View All Users', href: '/admin/users' },
              { label: 'Add New User', href: '/admin/users/new' },
              { label: 'Manage Roles', href: '/admin/roles' },
            ]}
          />

          {/* Video Processing */}
          <AdminSection
            title="Video Processing"
            description="Monitor and manage video processing queue"
            icon="🎥"
            actions={[
              { label: 'Processing Queue', href: '/admin/queue' },
              { label: 'Failed Jobs', href: '/admin/failed-jobs' },
              { label: 'Backups', href: '/admin/backups' },
              { label: 'Processing Stats', href: '/admin/stats' },
            ]}
          />

          {/* System Settings */}
          <AdminSection
            title="System Settings"
            description="Configure application settings and integrations"
            icon="⚙️"
            actions={[
              { label: 'General Settings', href: '/admin/settings' },
              { label: 'API Keys', href: '/admin/api-keys' },
              { label: 'Integrations', href: '/admin/integrations' },
            ]}
          />

          {/* Analytics */}
          <AdminSection
            title="Analytics"
            description="View usage statistics and performance metrics"
            icon="📊"
            actions={[
              { label: 'Usage Dashboard', href: '/admin/analytics' },
              { label: 'Performance Metrics', href: '/admin/performance' },
              { label: 'Export Reports', href: '/admin/reports' },
            ]}
          />
        </div>

        {/* Quick Actions */}
        <div className="mt-8 bg-white dark:bg-gray-800/50 rounded-lg shadow-md dark:shadow-none border border-transparent dark:border-gray-700/50 p-6">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Quick Actions</h2>
          <div className="flex flex-wrap gap-3">
            <QuickActionButton
              label="Refresh Data"
              onClick={() => alert('Refresh functionality coming soon')}
            />
            <QuickActionButton
              label="Clear Cache"
              onClick={() => alert('Clear cache functionality coming soon')}
            />
            <QuickActionButton
              label="Run Diagnostics"
              onClick={() => alert('Diagnostics functionality coming soon')}
            />
            <QuickActionButton
              label="Export Logs"
              onClick={() => alert('Export logs functionality coming soon')}
            />
          </div>
        </div>

        {/* Footer Note */}
        <div className="mt-8 text-center text-sm text-gray-500 dark:text-gray-400">
          <p>Admin dashboard is only accessible to users with administrator privileges.</p>
          <p className="mt-1">This page is protected by role-based access control.</p>
        </div>
      </div>
    </div>
  );
}

/* Supporting Components */

interface StatCardProps {
  title: string;
  value: string;
  description: string;
  icon: string;
  color: 'blue' | 'green' | 'yellow' | 'purple';
}

function StatCard({ title, value, description, icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'from-blue-500 to-blue-600',
    green: 'from-green-500 to-green-600',
    yellow: 'from-yellow-500 to-yellow-600',
    purple: 'from-purple-500 to-purple-600',
  };

  return (
    <div className={`bg-gradient-to-br ${colorClasses[color]} rounded-lg shadow-md p-6 text-white`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold">{title}</h3>
        <span className="text-3xl">{icon}</span>
      </div>
      <p className="text-3xl font-bold mb-1">{value}</p>
      <p className="text-sm opacity-90">{description}</p>
    </div>
  );
}

interface AdminSectionProps {
  title: string;
  description: string;
  icon: string;
  actions: Array<{ label: string; href: string }>;
}

function AdminSection({ title, description, icon, actions }: AdminSectionProps) {
  return (
    <div className="bg-white dark:bg-gray-800/50 rounded-lg shadow-md dark:shadow-none border border-transparent dark:border-gray-700/50 p-6">
      <div className="flex items-center mb-3">
        <span className="text-3xl mr-3">{icon}</span>
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{title}</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400">{description}</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {actions.map((action, index) => (
          <a
            key={index}
            href={action.href}
            className="block w-full text-left px-4 py-2 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md transition-colors"
          >
            {action.label} →
          </a>
        ))}
      </div>
    </div>
  );
}

function QuickActionButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors shadow-sm dark:shadow-none"
    >
      {label}
    </button>
  );
}

/**
 * Expedite Requests Panel for admin quota management
 */
function ExpediteRequestsPanel() {
  const [requests, setRequests] = useState<ExpediteRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  const loadRequests = async () => {
    try {
      const data = await adminQuotaApi.listRequests('pending');
      setRequests(data.requests);
    } catch {
      // Silently fail — endpoint may not be deployed yet
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, []);

  const handleApprove = async (requestId: string) => {
    setActionInProgress(requestId);
    try {
      await adminQuotaApi.approve(requestId);
      await loadRequests();
    } catch (err) {
      alert(`Failed to approve: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleDeny = async (requestId: string) => {
    setActionInProgress(requestId);
    try {
      await adminQuotaApi.deny(requestId);
      await loadRequests();
    } catch (err) {
      alert(`Failed to deny: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setActionInProgress(null);
    }
  };

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800/50 rounded-lg shadow-md dark:shadow-none border border-transparent dark:border-gray-700/50 p-6">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
          ⚡ Expedite Requests
        </h2>
        <p className="text-gray-500 dark:text-gray-400">Loading...</p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800/50 rounded-lg shadow-md dark:shadow-none border border-transparent dark:border-gray-700/50 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">⚡ Expedite Requests</h2>
        {requests.length > 0 && (
          <span className="px-2 py-1 text-xs font-semibold text-amber-700 dark:text-amber-300 bg-amber-100 dark:bg-amber-900/50 rounded-full">
            {requests.length} pending
          </span>
        )}
      </div>

      {requests.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400 text-sm">No pending expedite requests.</p>
      ) : (
        <div className="space-y-3">
          {requests.map((req) => (
            <div
              key={req.request_id}
              className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600"
            >
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-gray-900 dark:text-white">
                    {req.video_count} videos queued
                  </span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    {new Date(req.created_at).toLocaleDateString()}
                  </span>
                </div>
                {req.reason && (
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    &quot;{req.reason}&quot;
                  </p>
                )}
              </div>
              <div className="flex gap-2 ml-4">
                <button
                  onClick={() => handleApprove(req.request_id)}
                  disabled={actionInProgress === req.request_id}
                  className="px-3 py-1.5 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                  Approve
                </button>
                <button
                  onClick={() => handleDeny(req.request_id)}
                  disabled={actionInProgress === req.request_id}
                  className="px-3 py-1.5 text-sm bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 transition-colors"
                >
                  Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
