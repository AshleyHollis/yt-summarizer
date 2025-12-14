/**
 * Tests for VideoCard component
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { VideoCard } from '@/components/library/VideoCard';
import type { VideoCard as VideoCardType } from '@/services/api';

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
      render(<VideoCard video={mockVideo} />);

      expect(screen.getByText('Test Video Title')).toBeInTheDocument();
    });

    it('renders channel name', () => {
      render(<VideoCard video={mockVideo} />);

      expect(screen.getByText('Test Channel')).toBeInTheDocument();
    });

    it('renders formatted duration', () => {
      render(<VideoCard video={mockVideo} />);

      // 215 seconds = 3:35
      expect(screen.getByText('3:35')).toBeInTheDocument();
    });

    it('renders processing status badge', () => {
      render(<VideoCard video={mockVideo} />);

      expect(screen.getByText('completed')).toBeInTheDocument();
    });

    it('renders segment count when available', () => {
      render(<VideoCard video={mockVideo} />);

      expect(screen.getByText('25 segments')).toBeInTheDocument();
    });

    it('renders facet tags', () => {
      render(<VideoCard video={mockVideo} />);

      expect(screen.getByText('Python')).toBeInTheDocument();
      expect(screen.getByText('Tutorial')).toBeInTheDocument();
    });

    it('links to video detail page', () => {
      render(<VideoCard video={mockVideo} />);

      const link = screen.getByRole('link');
      expect(link).toHaveAttribute(
        'href',
        `/library/${mockVideo.video_id}`
      );
    });

    it('uses thumbnail URL from video', () => {
      render(<VideoCard video={mockVideo} />);

      const thumbnail = screen.getByTestId('video-thumbnail');
      expect(thumbnail).toHaveAttribute('src', mockVideo.thumbnail_url);
    });

    it('uses YouTube thumbnail as fallback when thumbnail_url is null', () => {
      const videoWithoutThumbnail = { ...mockVideo, thumbnail_url: null };
      render(<VideoCard video={videoWithoutThumbnail} />);

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
      render(<VideoCard video={shortVideo} />);

      // 65 seconds = 1:05
      expect(screen.getByText('1:05')).toBeInTheDocument();
    });

    it('formats long duration with hours', () => {
      const longVideo = { ...mockVideo, duration: 3725 };
      render(<VideoCard video={longVideo} />);

      // 3725 seconds = 1:02:05
      expect(screen.getByText('1:02:05')).toBeInTheDocument();
    });
  });

  describe('Status badges', () => {
    it('renders pending status', () => {
      const pendingVideo = { ...mockVideo, processing_status: 'pending' };
      render(<VideoCard video={pendingVideo} />);

      expect(screen.getByText('pending')).toBeInTheDocument();
    });

    it('renders processing status', () => {
      const processingVideo = { ...mockVideo, processing_status: 'processing' };
      render(<VideoCard video={processingVideo} />);

      expect(screen.getByText('processing')).toBeInTheDocument();
    });

    it('renders failed status', () => {
      const failedVideo = { ...mockVideo, processing_status: 'failed' };
      render(<VideoCard video={failedVideo} />);

      expect(screen.getByText('failed')).toBeInTheDocument();
    });
  });

  describe('Facets display', () => {
    it('shows only first 3 facets when more than 3 exist', () => {
      const manyFacetsVideo = {
        ...mockVideo,
        facets: [
          { facet_id: 'f1', name: 'Facet1', type: 'topic' },
          { facet_id: 'f2', name: 'Facet2', type: 'topic' },
          { facet_id: 'f3', name: 'Facet3', type: 'format' },
          { facet_id: 'f4', name: 'Facet4', type: 'level' },
          { facet_id: 'f5', name: 'Facet5', type: 'tool' },
        ],
      };
      render(<VideoCard video={manyFacetsVideo} />);

      expect(screen.getByText('Facet1')).toBeInTheDocument();
      expect(screen.getByText('Facet2')).toBeInTheDocument();
      expect(screen.getByText('Facet3')).toBeInTheDocument();
      expect(screen.queryByText('Facet4')).not.toBeInTheDocument();
      expect(screen.getByText('+2')).toBeInTheDocument();
    });

    it('does not show +N badge when 3 or fewer facets', () => {
      render(<VideoCard video={mockVideo} />);

      expect(screen.queryByText(/^\+\d+$/)).not.toBeInTheDocument();
    });
  });
});
