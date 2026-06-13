import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import BackupDashboardPage from '@/app/admin/backups/page';
import { adminBackupApi } from '@/services/api';
import { useAuth } from '@/hooks/useAuth';
import type { AuthContextValue } from '@/contexts/AuthContext';

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@/services/api', () => ({
  adminBackupApi: {
    getStatus: vi.fn(),
    listRuns: vi.fn(),
  },
}));

const activeRun = {
  job_id: 'job-1',
  run_id: '20260609T160000Z-test',
  status: 'running',
  stage: 'running',
  progress: 40,
  started_at: '2026-06-09T16:00:00Z',
  completed_at: null,
  current_channel: 'mark-wildman',
  total_channels: 1,
  completed_channels: 0,
  copied_blobs: 2,
  skipped_blobs: 3,
  missing_blobs: 0,
  bytes_copied: 2048,
  warning_count: 0,
  warnings: [],
  report_blob_path: null,
  error_message: null,
  channels: [
    {
      slug: 'mark-wildman',
      name: 'Mark Wildman',
      status: 'running',
      phase: 'copying',
      total_videos: 10,
      processed_videos: 4,
      copied_blobs: 2,
      skipped_blobs: 3,
      missing_blobs: 0,
      bytes_copied: 2048,
      warnings: [],
    },
  ],
};

describe('BackupDashboardPage', () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({
      user: {
        sub: 'auth0|admin',
        email: 'admin@example.com',
        email_verified: true,
        'https://yt-summarizer.com/role': 'admin',
        updated_at: '2026-06-09T00:00:00Z',
      },
      isLoading: false,
      error: null,
      isAuthenticated: true,
      hasRole: (role) => role === 'admin',
    } satisfies AuthContextValue);
    vi.mocked(adminBackupApi.getStatus).mockResolvedValue({ latest_run: activeRun });
    vi.mocked(adminBackupApi.listRuns).mockResolvedValue({ runs: [activeRun], total: 1 });
  });

  it('renders active backup run progress', async () => {
    render(<BackupDashboardPage />);

    expect(await screen.findByText('Latest run')).toBeInTheDocument();
    expect(screen.getAllByText('20260609T160000Z-test')[0]).toBeInTheDocument();
    expect(screen.getByText('Mark Wildman')).toBeInTheDocument();
    expect(screen.getByText('4/10 videos')).toBeInTheDocument();
    expect(screen.getAllByText('2 KB')).toHaveLength(2);
  });
});
