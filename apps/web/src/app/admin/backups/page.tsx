'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  DatabaseBackup,
  HardDrive,
  RefreshCw,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { adminBackupApi, type BackupChannelProgress, type BackupRunSummary } from '@/services/api';

const ACTIVE_STATUSES = new Set(['pending', 'running']);

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = size >= 10 || unitIndex === 0 || Number.isInteger(size) ? 0 : 1;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function formatDateTime(value: string | null): string {
  if (!value) return 'Not yet';
  return new Date(value).toLocaleString();
}

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const classes =
    normalized === 'succeeded'
      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200'
      : normalized === 'suspect'
        ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200'
        : normalized === 'failed'
          ? 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200'
          : 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200';

  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ${classes}`}
    >
      {status}
    </span>
  );
}

function StatTile({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: LucideIcon;
}) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800/50">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</span>
        <Icon className="h-4 w-4 text-gray-400" aria-hidden="true" />
      </div>
      <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">{value}</p>
    </div>
  );
}

function ChannelRow({ channel }: { channel: BackupChannelProgress }) {
  const percent =
    channel.total_videos > 0
      ? Math.min(100, Math.round((channel.processed_videos / channel.total_videos) * 100))
      : 0;

  return (
    <tr className="border-t border-gray-200 dark:border-gray-700">
      <td className="px-4 py-3">
        <div className="font-medium text-gray-900 dark:text-white">
          {channel.name || channel.slug}
        </div>
        <div className="text-xs text-gray-500 dark:text-gray-400">{channel.slug}</div>
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={channel.status} />
      </td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
        {channel.phase || 'queued'}
      </td>
      <td className="px-4 py-3">
        <div className="h-2 w-40 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-700">
          <div className="h-full bg-blue-600" style={{ width: `${percent}%` }} />
        </div>
        <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          {channel.processed_videos}/{channel.total_videos} videos
        </div>
      </td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">{channel.copied_blobs}</td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
        {channel.skipped_blobs}
      </td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
        {formatBytes(channel.bytes_copied)}
      </td>
    </tr>
  );
}

export default function BackupDashboardPage() {
  const router = useRouter();
  const { isLoading, isAuthenticated, hasRole } = useAuth();
  const [latestRun, setLatestRun] = useState<BackupRunSummary | null>(null);
  const [runs, setRuns] = useState<BackupRunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.replace('/sign-in');
    } else if (!hasRole('admin')) {
      router.replace('/forbidden');
    }
  }, [hasRole, isAuthenticated, isLoading, router]);

  const loadBackups = useCallback(async () => {
    setRefreshing(true);
    try {
      const [status, runList] = await Promise.all([
        adminBackupApi.getStatus(),
        adminBackupApi.listRuns(30),
      ]);
      setLatestRun(status.latest_run);
      setRuns(runList.runs);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load backup status');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!isAuthenticated || !hasRole('admin')) return;
    loadBackups();
  }, [hasRole, isAuthenticated, loadBackups]);

  const isActive = latestRun ? ACTIVE_STATUSES.has(latestRun.status) : false;

  useEffect(() => {
    if (!isAuthenticated || !hasRole('admin')) return;
    const intervalMs = isActive ? 5000 : 60000;
    const id = window.setInterval(loadBackups, intervalMs);
    return () => window.clearInterval(id);
  }, [hasRole, isActive, isAuthenticated, loadBackups]);

  const activeIcon = useMemo(() => {
    if (!latestRun) return Clock;
    if (latestRun.status === 'succeeded') return CheckCircle2;
    if (latestRun.status === 'failed') return XCircle;
    if (latestRun.status === 'suspect') return AlertTriangle;
    return Activity;
  }, [latestRun]);

  if (isLoading || loading) {
    return (
      <main className="min-h-screen bg-gray-50 px-4 py-8 dark:bg-[#0f0f0f]">
        <div className="mx-auto max-w-7xl">
          <div className="h-8 w-48 animate-pulse rounded bg-gray-200 dark:bg-gray-800" />
          <div className="mt-6 h-64 animate-pulse rounded-lg bg-gray-200 dark:bg-gray-800" />
        </div>
      </main>
    );
  }

  if (!isAuthenticated || !hasRole('admin')) return null;

  const ActiveIcon = activeIcon;

  return (
    <main className="min-h-screen bg-gray-50 px-4 py-8 dark:bg-[#0f0f0f]">
      <div className="mx-auto max-w-7xl">
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <Link href="/admin" className="text-sm text-blue-600 hover:text-blue-700">
              Admin
            </Link>
            <h1 className="mt-2 text-3xl font-semibold text-gray-900 dark:text-white">Backups</h1>
          </div>
          <button
            type="button"
            onClick={loadBackups}
            disabled={refreshing}
            className="inline-flex items-center justify-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200">
            {error}
          </div>
        )}

        {!latestRun ? (
          <section className="rounded-lg border border-gray-200 bg-white p-8 text-center dark:border-gray-700 dark:bg-gray-800/50">
            <DatabaseBackup className="mx-auto h-10 w-10 text-gray-400" aria-hidden="true" />
            <h2 className="mt-4 text-lg font-semibold text-gray-900 dark:text-white">
              No backup runs yet
            </h2>
          </section>
        ) : (
          <>
            <section className="rounded-lg border border-gray-200 bg-white p-5 dark:border-gray-700 dark:bg-gray-800/50">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex items-start gap-3">
                  <div className="rounded-lg bg-blue-50 p-2 text-blue-600 dark:bg-blue-950/40 dark:text-blue-300">
                    <ActiveIcon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-3">
                      <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Latest run
                      </h2>
                      <StatusBadge status={latestRun.status} />
                    </div>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                      {latestRun.run_id}
                    </p>
                  </div>
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-300">
                  Started {formatDateTime(latestRun.started_at)}
                </div>
              </div>

              <div className="mt-5">
                <div className="mb-2 flex items-center justify-between text-sm text-gray-600 dark:text-gray-300">
                  <span>
                    {latestRun.completed_channels}/{latestRun.total_channels} channels
                  </span>
                  <span>{latestRun.progress}%</span>
                </div>
                <div className="h-3 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-700">
                  <div className="h-full bg-blue-600" style={{ width: `${latestRun.progress}%` }} />
                </div>
              </div>
            </section>

            <section className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatTile
                label="Copied"
                value={String(latestRun.copied_blobs)}
                icon={DatabaseBackup}
              />
              <StatTile label="Skipped" value={String(latestRun.skipped_blobs)} icon={Activity} />
              <StatTile
                label="Bytes copied"
                value={formatBytes(latestRun.bytes_copied)}
                icon={HardDrive}
              />
              <StatTile
                label="Warnings"
                value={String(latestRun.warning_count)}
                icon={AlertTriangle}
              />
            </section>

            {latestRun.warnings.length > 0 && (
              <section className="mt-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-900/60 dark:bg-amber-950/30">
                <h2 className="text-sm font-semibold text-amber-900 dark:text-amber-100">
                  Warnings
                </h2>
                <ul className="mt-2 space-y-1 text-sm text-amber-800 dark:text-amber-200">
                  {latestRun.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </section>
            )}

            <section className="mt-6 overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800/50">
              <div className="border-b border-gray-200 px-4 py-3 dark:border-gray-700">
                <h2 className="font-semibold text-gray-900 dark:text-white">Channels</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-left">
                  <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-gray-900/40 dark:text-gray-400">
                    <tr>
                      <th className="px-4 py-3">Channel</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Phase</th>
                      <th className="px-4 py-3">Progress</th>
                      <th className="px-4 py-3">Copied</th>
                      <th className="px-4 py-3">Skipped</th>
                      <th className="px-4 py-3">Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestRun.channels.map((channel) => (
                      <ChannelRow key={channel.slug} channel={channel} />
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        <section className="mt-6 overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800/50">
          <div className="border-b border-gray-200 px-4 py-3 dark:border-gray-700">
            <h2 className="font-semibold text-gray-900 dark:text-white">Recent Runs</h2>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {runs.length === 0 ? (
              <p className="p-4 text-sm text-gray-500 dark:text-gray-400">No recent runs.</p>
            ) : (
              runs.map((run) => (
                <div
                  key={run.job_id}
                  className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-gray-900 dark:text-white">
                        {run.run_id}
                      </span>
                      <StatusBadge status={run.status} />
                    </div>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                      {formatDateTime(run.started_at)} · {run.completed_channels}/
                      {run.total_channels} channels · {formatBytes(run.bytes_copied)}
                    </p>
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-300">
                    {run.report_blob_path || 'Report pending'}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </main>
  );
}
