/**
 * Tests for Video Detail Page Reprocess Button functionality
 *
 * Tests T180: Add "Reprocess" button to video detail page for videos
 * with failed/empty transcripts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

// Mock the next/navigation hooks
vi.mock('next/navigation', () => ({
  useParams: () => ({ videoId: 'test-video-id' }),
  useRouter: () => ({ push: vi.fn() }),
}));

// Mock the providers context
vi.mock('@/app/providers', () => ({
  useVideoContext: () => ({
    setCurrentVideo: vi.fn(),
  }),
}));

// Mock the API modules
vi.mock('@/services/api', () => ({
  libraryApi: {
    getVideoDetail: vi.fn(),
  },
  videoApi: {
    reprocess: vi.fn(),
  },
}));

import { libraryApi, videoApi } from '@/services/api';

// Create a mock video response factory
const createMockVideoDetail = (overrides = {}) => ({
  video_id: 'test-video-id',
  youtube_video_id: 'abc123',
  youtube_url: 'https://youtube.com/watch?v=abc123',
  title: 'Test Video Title',
  description: 'Test description',
  duration: 300,
  publish_date: '2024-01-15T10:00:00Z',
  thumbnail_url: 'https://img.youtube.com/vi/abc123/maxresdefault.jpg',
  processing_status: 'completed',
  channel: {
    channel_id: 'channel-1',
    name: 'Test Channel',
    youtube_channel_id: 'UC12345',
  },
  facets: [],
  summary: 'This is a test summary with content.',
  transcript: 'Test transcript content',
  ...overrides,
});

describe('Video Detail Page - Reprocess Button', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Visibility Logic', () => {
    it('shows reprocess button for failed videos', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );

      // Import and render the page component
      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });
    });

    it('shows reprocess button for completed videos with missing summary', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'completed', summary: null })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });
    });

    it('shows reprocess button for completed videos with empty summary', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'completed', summary: '   ' })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });
    });

    it('does NOT show reprocess button for completed videos with valid summary', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'completed', summary: 'Valid summary content' })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      // Wait for the page to load
      await waitFor(() => {
        expect(screen.getByText('Test Video Title')).toBeInTheDocument();
      }, { timeout: 5000 });

      // Reprocess button should NOT be visible
      expect(screen.queryByRole('button', { name: /Reprocess Video/i })).not.toBeInTheDocument();
    });

    it('does NOT show reprocess button while video is still processing', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'processing', summary: null })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByText('Test Video Title')).toBeInTheDocument();
      }, { timeout: 5000 });

      // Should not show reprocess since it's still processing
      expect(screen.queryByRole('button', { name: /Reprocess Video/i })).not.toBeInTheDocument();
    });
  });

  describe('Click Behavior', () => {
    it('calls videoApi.reprocess when button is clicked', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );
      vi.mocked(videoApi.reprocess).mockResolvedValue({ video_id: 'test-video-id' });

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });

      const button = screen.getByRole('button', { name: /Reprocess Video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(videoApi.reprocess).toHaveBeenCalledWith('test-video-id');
      });
    });

    it('shows loading state while reprocessing', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );

      // Delay the reprocess response to test loading state
      vi.mocked(videoApi.reprocess).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ video_id: 'test-video-id' }), 500))
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });

      const button = screen.getByRole('button', { name: /Reprocess Video/i });
      fireEvent.click(button);

      // Should show loading text
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Starting reprocess/i })).toBeInTheDocument();
      });
    });

    it('disables button while reprocessing', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );

      vi.mocked(videoApi.reprocess).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ video_id: 'test-video-id' }), 500))
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });

      const button = screen.getByRole('button', { name: /Reprocess Video/i });
      fireEvent.click(button);

      await waitFor(() => {
        const loadingButton = screen.getByRole('button', { name: /Starting reprocess/i });
        expect(loadingButton).toBeDisabled();
      });
    });
  });

  describe('Error Handling', () => {
    it('shows error message when reprocess fails', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );
      vi.mocked(videoApi.reprocess).mockRejectedValue(new Error('API Error'));

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });

      const button = screen.getByRole('button', { name: /Reprocess Video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByText(/Failed to start reprocessing/i)).toBeInTheDocument();
      });
    });

    it('button is re-enabled after error', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );
      vi.mocked(videoApi.reprocess).mockRejectedValue(new Error('API Error'));

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Reprocess Video/i })).toBeInTheDocument();
      }, { timeout: 5000 });

      const button = screen.getByRole('button', { name: /Reprocess Video/i });
      fireEvent.click(button);

      // Wait for error to appear
      await waitFor(() => {
        expect(screen.getByText(/Failed to start reprocessing/i)).toBeInTheDocument();
      });

      // Button should be enabled again
      const reenabledButton = screen.getByRole('button', { name: /Reprocess Video/i });
      expect(reenabledButton).not.toBeDisabled();
    });
  });

  describe('Contextual Messaging', () => {
    it('shows failure-specific message for failed videos', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'failed', summary: null })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByText(/Processing failed for this video/i)).toBeInTheDocument();
      }, { timeout: 5000 });
    });

    it('shows missing content message for completed videos without summary', async () => {
      vi.mocked(libraryApi.getVideoDetail).mockResolvedValue(
        createMockVideoDetail({ processing_status: 'completed', summary: null })
      );

      const { default: VideoDetailPage } = await import('@/app/library/[videoId]/page');
      render(<VideoDetailPage />);

      await waitFor(() => {
        expect(screen.getByText(/Missing content detected/i)).toBeInTheDocument();
      }, { timeout: 5000 });
    });
  });
});
