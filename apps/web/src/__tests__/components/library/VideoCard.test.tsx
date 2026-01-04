/**
 * Tests for VideoCard component
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { VideoCard } from '@/components/library/VideoCard';
import { VideoSelectionProvider } from '@/contexts/VideoSelectionContext';
import type { VideoCard as VideoCardType } from '@/services/api';

// Helper to render with required providers
const renderVideoCard = (props: { video: VideoCardType }) => {
  return render(
    <VideoSelectionProvider>
      <VideoCard {...props} />
    </VideoSelectionProvider>
  );
};

// Mock next/image
vi.mock('next/image', () => ({
  default: (props: { alt: string; src: string }) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img alt={props.alt} src={props.src} data-testid="video-thumbnail" />
  ),
}));

// Mock next/link
vi.mock('next/link', () => ({
  default: ({
    children,
    href,
  }: {
    children: React.ReactNode;
    href: string;
  }) => <a href={href}>{children}</a>,
}));

describe('VideoCard', () => {
  const mockVideo: VideoCardType = {
    video_id: '123e4567-e89b-12d3-a456-426614174000',
    youtube_video_id: 'dQw4w9WgXcQ',
    title: 'Test Video Title',
    channel_id: '123e4567-e89b-12d3-a456-426614174001',
    channel_name: 'Test Channel',
    duration: 215,
    publish_date: '2024-01-15T10:30:00Z',
    thumbnail_url: 'https://example.com/thumbnail.jpg',
    processing_status: 'completed',
    segment_count: 25,
    facets: [
      { facet_id: 'facet-1', name: 'Python', type: 'topic' },
      { facet_id: 'facet-2', name: 'Tutorial', type: 'format' },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders video title', () => {
      renderVideoCard({ video: mockVideo });

      expect(screen.getByText('Test Video Title')).toBeInTheDocument();
    });

    it('renders channel name', () => {
      renderVideoCard({ video: mockVideo });

      expect(screen.getByText('Test Channel')).toBeInTheDocument();
    });

    it('renders formatted duration', () => {
      renderVideoCard({ video: mockVideo });

      // 215 seconds = 3:35
      expect(screen.getByText('3:35')).toBeInTheDocument();
    });

    it('hides status badge for completed videos', () => {
      renderVideoCard({ video: mockVideo });

      // Completed status badge is intentionally hidden for cleaner UI
      expect(screen.queryByText('completed')).not.toBeInTheDocument();
    });

    it('shows status badge for non-completed videos', () => {
      const pendingVideo = { ...mockVideo, processing_status: 'pending' };
      renderVideoCard({ video: pendingVideo });

      expect(screen.getByText('pending')).toBeInTheDocument();
    });

    it('links to video detail page', () => {
      renderVideoCard({ video: mockVideo });

      const link = screen.getByRole('link');
      expect(link).toHaveAttribute(
        'href',
        `/library/${mockVideo.video_id}`
      );
    });

    it('uses thumbnail URL from video', () => {
      renderVideoCard({ video: mockVideo });

      const thumbnail = screen.getByTestId('video-thumbnail');
      expect(thumbnail).toHaveAttribute('src', mockVideo.thumbnail_url);
    });

    it('uses YouTube thumbnail as fallback when thumbnail_url is null', () => {
      const videoWithoutThumbnail = { ...mockVideo, thumbnail_url: null };
      renderVideoCard({ video: videoWithoutThumbnail });

      const thumbnail = screen.getByTestId('video-thumbnail');
      expect(thumbnail).toHaveAttribute(
        'src',
        `https://img.youtube.com/vi/${mockVideo.youtube_video_id}/mqdefault.jpg`
      );
    });
  });

  describe('Duration formatting', () => {
    it('formats short duration correctly', () => {
      const shortVideo = { ...mockVideo, duration: 65 };
      renderVideoCard({ video: shortVideo });

      // 65 seconds = 1:05
      expect(screen.getByText('1:05')).toBeInTheDocument();
    });

    it('formats long duration with hours', () => {
      const longVideo = { ...mockVideo, duration: 3725 };
      renderVideoCard({ video: longVideo });

      // 3725 seconds = 1:02:05
      expect(screen.getByText('1:02:05')).toBeInTheDocument();
    });
  });

  describe('Status badges', () => {
    it('renders pending status', () => {
      const pendingVideo = { ...mockVideo, processing_status: 'pending' };
      renderVideoCard({ video: pendingVideo });

      expect(screen.getByText('pending')).toBeInTheDocument();
    });

    it('renders processing status', () => {
      const processingVideo = { ...mockVideo, processing_status: 'processing' };
      renderVideoCard({ video: processingVideo });

      expect(screen.getByText('processing')).toBeInTheDocument();
    });

    it('renders failed status', () => {
      const failedVideo = { ...mockVideo, processing_status: 'failed' };
      renderVideoCard({ video: failedVideo });

      expect(screen.getByText('failed')).toBeInTheDocument();
    });
  });

  // Note: VideoCard component has been redesigned to be minimal/YouTube-style
  // and no longer displays facets. These tests are kept for documentation.
  describe('Minimal card design', () => {
    it('does not show facets (minimal YouTube-style design)', () => {
      renderVideoCard({ video: mockVideo });

      // Facets are not displayed in the minimal card design
      expect(screen.queryByText('Python')).not.toBeInTheDocument();
      expect(screen.queryByText('Tutorial')).not.toBeInTheDocument();
    });

    it('does not show segment count (minimal design)', () => {
      renderVideoCard({ video: mockVideo });

      expect(screen.queryByText('25 segments')).not.toBeInTheDocument();
    });
  });
});
