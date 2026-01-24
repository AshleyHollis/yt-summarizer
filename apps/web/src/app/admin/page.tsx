'use client';

import Link from 'next/link';

export default function AdminDashboard() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Admin Dashboard</h1>
          <p className="text-gray-600">Authentication is handled by the backend API.</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link
              href="/api/auth/login"
              className="inline-flex items-center rounded-lg bg-gray-900 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-gray-800"
            >
              Sign in with Auth0
            </Link>
            <Link
              href="/api/auth/logout"
              className="inline-flex items-center rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50"
            >
              Sign out
            </Link>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard title="Total Users" value="--" description="Registered users" icon="👥" color="blue" />
          <StatCard title="Videos Processed" value="--" description="All time" icon="🎥" color="green" />
          <StatCard title="Active Sessions" value="--" description="Currently online" icon="🔄" color="yellow" />
          <StatCard title="System Health" value="Good" description="All services operational" icon="✅" color="purple" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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

        <div className="mt-8 bg-white rounded-lg shadow-md p-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Quick Actions</h2>
          <div className="flex flex-wrap gap-3">
            <QuickActionButton label="Refresh Data" onClick={() => alert('Refresh functionality coming soon')} />
            <QuickActionButton label="Clear Cache" onClick={() => alert('Clear cache functionality coming soon')} />
            <QuickActionButton label="Run Diagnostics" onClick={() => alert('Diagnostics functionality coming soon')} />
            <QuickActionButton label="Export Logs" onClick={() => alert('Export logs functionality coming soon')} />
          </div>
        </div>

        <div className="mt-8 text-center text-sm text-gray-500">
          <p>Admin access is enforced by the backend Auth0 proxy.</p>
        </div>
      </div>
    </div>
  );
}

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
      <div className="flex items-center gap-3 mb-4">
        <span className="text-2xl">{icon}</span>
        <div>
          <h3 className="text-lg font-bold text-gray-900">{title}</h3>
          <p className="text-sm text-gray-600">{description}</p>
        </div>
      </div>
      <div className="space-y-2">
        {actions.map((action) => (
          <Link
            key={action.href}
            href={action.href}
            className="flex items-center justify-between rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700 transition hover:bg-gray-50"
          >
            <span>{action.label}</span>
            <span className="text-gray-400">→</span>
          </Link>
        ))}
      </div>
    </div>
  );
}

interface QuickActionButtonProps {
  label: string;
  onClick: () => void;
}

function QuickActionButton({ label, onClick }: QuickActionButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center rounded-lg border border-gray-200 bg-white px-4 py-2 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50"
    >
      {label}
    </button>
  );
}
