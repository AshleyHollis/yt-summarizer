/**
 * Admin Dashboard Page
 *
 * This page is protected by middleware and only accessible to users with the 'admin' role.
 * It provides administrative functions for managing the YouTube Summarizer application.
 *
 * Protection:
 * - Middleware checks authentication and admin role
 * - Unauthenticated users → Redirected to /login
 * - Non-admin users → Redirected to /access-denied
 *
 * Features:
 * - User management overview
 * - System statistics
 * - Application settings
 * - Video processing monitoring
 */

'use client';

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../hooks/useAuth';

export default function AdminDashboard() {
  const { user, isLoading, isAuthenticated, hasRole } = useAuth();
  const router = useRouter();

  // Client-side auth guard — defense in depth alongside the proxy layer.
  // Redirects if the proxy did not (e.g. Auth0 not configured in dev, or direct fetch).
  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.replace('/login');
    } else if (!hasRole('admin')) {
      router.replace('/access-denied');
    }
  }, [isLoading, isAuthenticated, hasRole, router]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        <span className="ml-3 text-lg">Loading admin dashboard...</span>
      </div>
    );
  }

  // Render nothing while redirect is in flight (prevents content flash)
  if (!isAuthenticated || !hasRole('admin')) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Admin Dashboard</h1>
          <p className="text-gray-600">Welcome, {user?.email || 'Administrator'}</p>
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
        <div className="mt-8 bg-white rounded-lg shadow-md p-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Quick Actions</h2>
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
        <div className="mt-8 text-center text-sm text-gray-500">
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
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center mb-3">
        <span className="text-3xl mr-3">{icon}</span>
        <div>
          <h2 className="text-xl font-bold text-gray-900">{title}</h2>
          <p className="text-sm text-gray-600">{description}</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {actions.map((action, index) => (
          <a
            key={index}
            href={action.href}
            className="block w-full text-left px-4 py-2 text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
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
      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors shadow-sm"
    >
      {label}
    </button>
  );
}
