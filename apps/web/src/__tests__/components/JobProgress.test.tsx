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
            createMockJobSummary({
              job_id: 'job-1',
              job_type: 'transcribe',
              stage: 'completed',
              status: 'succeeded',
            }),
            createMockJobSummary({
              job_id: 'job-2',
              job_type: 'summarize',
              stage: 'failed',
              status: 'failed',
            }),
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
