/**
 * Tests for JobProgress component
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { JobProgress } from '@/components/JobProgress';
import { createMockVideoJobsProgress, createMockJobSummary } from '../helpers/mockFactories';

// Mock the API module
vi.mock('@/services/api', () => ({
  jobApi: {
    getVideoProgress: vi.fn(),
  },
}));

import { jobApi } from '@/services/api';

const createMockProgress = (overrides = {}) => ({
  video_id: '123',
  overall_status: 'processing',
  overall_progress: 50,
  jobs: [
    { job_id: 'job-1', job_type: 'transcribe' as const, stage: 'completed' as const, status: 'succeeded' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
    { job_id: 'job-2', job_type: 'summarize' as const, stage: 'running' as const, status: 'running' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
    { job_id: 'job-3', job_type: 'embed' as const, stage: 'queued' as const, status: 'pending' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
    { job_id: 'job-4', job_type: 'build_relationships' as const, stage: 'queued' as const, status: 'pending' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
  ],
  eta: null,
  current_stage_name: null,
  ...overrides,
});

describe('JobProgress', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('shows loading skeleton when API call is pending', () => {
      vi.mocked(jobApi.getVideoProgress).mockImplementation(
        () => new Promise(() => {}) // Never resolves
      );

      render(<JobProgress videoId="123" />);

      // Loading shows animate-pulse skeleton
      expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
    });

    it('displays progress after API response', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('50%')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });

    it('displays stage labels after API response', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('Extracting Transcript')).toBeInTheDocument();
          expect(screen.getByText('Generating Summary')).toBeInTheDocument();
          expect(screen.getByText('Creating Embeddings')).toBeInTheDocument();
          expect(screen.getByText('Finding Related Videos')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });

    it('shows Processing Progress heading', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('Processing Progress')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });
  });

  describe('Progress States', () => {
    it('shows 0% for zero progress', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(
        createMockVideoJobsProgress({ overall_progress: 0 })
      );

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('0%')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });

    it('shows "In progress..." text for running stage', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('In progress...')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });

    it('shows Processing Complete! message when done', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(
        createMockVideoJobsProgress({
          overall_status: 'completed',
          overall_progress: 100,
          jobs: [
            { job_id: 'job-1', job_type: 'transcribe' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-2', job_type: 'summarize' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-3', job_type: 'embed' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-4', job_type: 'build_relationships' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
          ],
        })
      );

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('Processing Complete!')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });

    it('shows Processing Failed message when failed', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(
        createMockVideoJobsProgress({
          overall_status: 'failed',
          jobs: [
            { job_id: 'job-1', job_type: 'transcribe' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-2', job_type: 'summarize' as const, status: 'failed' as const, stage: 'failed' as const, retry_count: 1, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-3', job_type: 'embed' as const, status: 'pending' as const, stage: 'queued' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-4', job_type: 'build_relationships' as const, status: 'pending' as const, stage: 'queued' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
          ],
        })
      );

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(screen.getByText('Processing Failed')).toBeInTheDocument();
        },
        { timeout: 10000 }
      );
    });
  });

  describe('Callbacks', () => {
    it('calls onComplete callback when overall_status is completed', async () => {
      const onComplete = vi.fn();
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(
        createMockVideoJobsProgress({ overall_status: 'completed', overall_progress: 100 })
      );

      render(<JobProgress videoId="123" onComplete={onComplete} />);

      await waitFor(
        () => {
          expect(onComplete).toHaveBeenCalled();
        },
        { timeout: 10000 }
      );
    });

    it('calls onFailed callback when overall_status is failed', async () => {
      const onFailed = vi.fn();
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(
        createMockVideoJobsProgress({
          overall_status: 'failed',
          jobs: [
            { job_id: 'job-1', job_type: 'transcribe' as const, status: 'succeeded' as const, stage: 'completed' as const, retry_count: 0, created_at: '2024-01-01T00:00:00Z' },
            { job_id: 'job-2', job_type: 'summarize' as const, status: 'failed' as const, stage: 'failed' as const, retry_count: 1, created_at: '2024-01-01T00:00:00Z' },
          ],
        })
      );

      render(<JobProgress videoId="123" onFailed={onFailed} />);

      await waitFor(
        () => {
          expect(onFailed).toHaveBeenCalledWith('summarize');
        },
        { timeout: 10000 }
      );
    });
  });

  describe('API calls', () => {
    it('fetches progress with videoId on mount', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          expect(jobApi.getVideoProgress).toHaveBeenCalledWith('123');
        },
        { timeout: 10000 }
      );
    });
  });

  describe('Accessibility', () => {
    it('has accessible progress bar', async () => {
      vi.mocked(jobApi.getVideoProgress).mockResolvedValue(createMockVideoJobsProgress());

      render(<JobProgress videoId="123" />);

      await waitFor(
        () => {
          const progressBar = document.querySelector('[role="progressbar"]');
          expect(progressBar).toBeInTheDocument();
          expect(progressBar).toHaveAttribute('aria-valuenow', '50');
          expect(progressBar).toHaveAttribute('aria-valuemin', '0');
          expect(progressBar).toHaveAttribute('aria-valuemax', '100');
        },
        { timeout: 10000 }
      );
    });
  });
});
