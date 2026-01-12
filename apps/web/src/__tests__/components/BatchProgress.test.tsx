/**
 * Tests for BatchProgress component
 *
 * These tests verify the BatchProgress component behavior by mocking
 * the batch API. Since EventSource is not available in JSDOM, the
 * component falls back to polling mode using batchApi.getById.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { BatchProgress } from '@/components/BatchProgress';
import { BatchDetailResponse } from '@/services/api';

// Mock the API module
vi.mock('@/services/api', () => ({
  batchApi: {
    getById: vi.fn(),
    streamProgress: vi.fn(),
    retryFailed: vi.fn(),
    retryItem: vi.fn(),
  },
}));

import { batchApi } from '@/services/api';

const createMockBatch = (overrides: Partial<BatchDetailResponse> = {}): BatchDetailResponse => ({
  id: 'batch-123',
  name: 'Test Batch - 12/14/2025',
  channel_name: 'Test Channel',
  status: 'running',
  total_count: 3,
  pending_count: 1,
  running_count: 1,
  succeeded_count: 1,
  failed_count: 0,
  created_at: '2025-12-14T10:00:00Z',
  updated_at: '2025-12-14T10:05:00Z',
  items: [
    {
      id: 'item-1',
      video_id: 'video-1',
      youtube_video_id: 'yt-123',
      title: 'Video 1',
      status: 'succeeded',
      error_message: null,
      created_at: '2025-12-14T10:00:00Z',
      updated_at: '2025-12-14T10:02:00Z',
    },
    {
      id: 'item-2',
      video_id: 'video-2',
      youtube_video_id: 'yt-456',
      title: 'Video 2',
      status: 'running',
      error_message: null,
      created_at: '2025-12-14T10:00:00Z',
      updated_at: '2025-12-14T10:03:00Z',
    },
    {
      id: 'item-3',
      video_id: 'video-3',
      youtube_video_id: 'yt-789',
      title: 'Video 3',
      status: 'pending',
      error_message: null,
      created_at: '2025-12-14T10:00:00Z',
      updated_at: '2025-12-14T10:00:00Z',
    },
  ],
  ...overrides,
});

describe('BatchProgress', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Loading state', () => {
    it('shows loading spinner initially', () => {
      // Mock getById to never resolve (stays in loading state)
      vi.mocked(batchApi.getById).mockImplementation(() => new Promise(() => {}));

      render(<BatchProgress batchId="batch-123" />);

      // Loading spinner should be visible
      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });
  });

  describe('Data display', () => {
    it('displays batch name after data loads', async () => {
      const mockBatch = createMockBatch();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText('Test Batch - 12/14/2025')).toBeInTheDocument();
      });
    });

    it('displays channel name after data loads', async () => {
      const mockBatch = createMockBatch();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText(/Test Channel/)).toBeInTheDocument();
      });
    });

    it('displays progress percentage', async () => {
      const mockBatch = createMockBatch({
        total_count: 4,
        succeeded_count: 2,
        failed_count: 0,
      });
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        // 2 completed out of 4 = 50% - text is rendered with space before %
        expect(screen.getByText(/50\s*%/)).toBeInTheDocument();
      });
    });

    it('displays video items', async () => {
      const mockBatch = createMockBatch();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText('Video 1')).toBeInTheDocument();
        expect(screen.getByText('Video 2')).toBeInTheDocument();
        expect(screen.getByText('Video 3')).toBeInTheDocument();
      });
    });

    it('displays total video count', async () => {
      const mockBatch = createMockBatch();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText(/3 videos/i)).toBeInTheDocument();
      });
    });
  });

  describe('Completion handling', () => {
    it('calls onComplete when batch is completed', async () => {
      const mockBatch = createMockBatch({
        status: 'completed',
        pending_count: 0,
        running_count: 0,
        succeeded_count: 3,
        failed_count: 0,
      });
      const onComplete = vi.fn();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" onComplete={onComplete} />);

      await waitFor(() => {
        expect(onComplete).toHaveBeenCalledWith(mockBatch);
      });
    });

    it('calls onComplete when all items are processed with failures', async () => {
      const mockBatch = createMockBatch({
        status: 'running',
        pending_count: 0,
        running_count: 0,
        succeeded_count: 2,
        failed_count: 1,
        total_count: 3,
      });
      const onComplete = vi.fn();
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" onComplete={onComplete} />);

      await waitFor(() => {
        expect(onComplete).toHaveBeenCalledWith(mockBatch);
      });
    });
  });

  describe('Retry functionality', () => {
    it('shows retry all button when batch has failed items', async () => {
      const mockBatch = createMockBatch({
        failed_count: 1,
        pending_count: 0,
        running_count: 0,
        succeeded_count: 2,
        items: [
          createMockBatch().items[0],
          createMockBatch().items[1],
          {
            id: 'item-3',
            video_id: 'video-3',
            youtube_video_id: 'yt-789',
            title: 'Failed Video',
            status: 'failed',
            error_message: 'Processing error',
            created_at: '2025-12-14T10:00:00Z',
            updated_at: '2025-12-14T10:04:00Z',
          },
        ],
      });
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        // Button says "Retry N Failed Video(s)"
        expect(screen.getByRole('button', { name: /Retry.*Failed/i })).toBeInTheDocument();
      });
    });

    it('shows error message for failed items', async () => {
      const mockBatch = createMockBatch({
        failed_count: 1,
        items: [
          createMockBatch().items[0],
          createMockBatch().items[1],
          {
            id: 'item-3',
            video_id: 'video-3',
            youtube_video_id: 'yt-789',
            title: 'Failed Video',
            status: 'failed',
            error_message: 'Processing error occurred',
            created_at: '2025-12-14T10:00:00Z',
            updated_at: '2025-12-14T10:04:00Z',
          },
        ],
      });
      vi.mocked(batchApi.getById).mockResolvedValue(mockBatch);

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText(/Processing error occurred/i)).toBeInTheDocument();
      });
    });
  });

  describe('Error handling', () => {
    it('shows error message when fetch fails', async () => {
      vi.mocked(batchApi.getById).mockRejectedValue(new Error('Network error'));

      render(<BatchProgress batchId="batch-123" />);

      await waitFor(() => {
        expect(screen.getByText(/Failed to fetch batch status/i)).toBeInTheDocument();
      });
    });
  });
});
