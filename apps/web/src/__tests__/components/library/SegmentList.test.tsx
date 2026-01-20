/**
 * Tests for SegmentList component
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { SegmentList } from '@/components/library/SegmentList';
import type { Segment } from '@/services/api';

// Mock heroicons
vi.mock('@heroicons/react/24/solid', () => ({
  PlayIcon: () => <span data-testid="play-icon">▶</span>,
}));

describe('SegmentList', () => {
  const mockSegments: Segment[] = [
    {
      segment_id: 'segment-1',
      sequence_number: 1,
      start_time: 0,
      end_time: 10.5,
      text: 'Hello and welcome to this video',
      youtube_url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=0',
    },
    {
      segment_id: 'segment-2',
      sequence_number: 2,
      start_time: 10.5,
      end_time: 25.3,
      text: 'Today we will be learning about Python',
      youtube_url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10',
    },
    {
      segment_id: 'segment-3',
      sequence_number: 3,
      start_time: 3661,
      end_time: 3680.5,
      text: 'This is over an hour into the video',
      youtube_url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=3661',
    },
  ];

  const mockYoutubeVideoId = 'dQw4w9WgXcQ';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders all segments', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      expect(screen.getByText('Hello and welcome to this video')).toBeInTheDocument();
      expect(screen.getByText('Today we will be learning about Python')).toBeInTheDocument();
      expect(screen.getByText('This is over an hour into the video')).toBeInTheDocument();
    });

    it('renders empty state when no segments', () => {
      render(<SegmentList segments={[]} youtubeVideoId={mockYoutubeVideoId} />);

      expect(screen.getByText('No transcript segments available.')).toBeInTheDocument();
    });

    it('renders timestamp links', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      const links = screen.getAllByRole('link');
      expect(links.length).toBe(3);
    });
  });

  describe('Timestamp formatting', () => {
    it('formats short timestamps as MM:SS', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      // 0 seconds = 0:00
      expect(screen.getByText('0:00')).toBeInTheDocument();
      // 10.5 seconds = 0:10
      expect(screen.getByText('0:10')).toBeInTheDocument();
    });

    it('formats long timestamps as HH:MM:SS', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      // 3661 seconds = 1:01:01
      expect(screen.getByText('1:01:01')).toBeInTheDocument();
    });
  });

  describe('YouTube links', () => {
    it('links to correct YouTube timestamp', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      const links = screen.getAllByRole('link');

      expect(links[0]).toHaveAttribute('href', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=0');
      expect(links[1]).toHaveAttribute('href', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10');
    });

    it('opens links in new tab', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      const links = screen.getAllByRole('link');
      links.forEach((link) => {
        expect(link).toHaveAttribute('target', '_blank');
        expect(link).toHaveAttribute('rel', 'noopener noreferrer');
      });
    });
  });

  describe('Segment text display', () => {
    it('displays segment text content', () => {
      render(<SegmentList segments={mockSegments} youtubeVideoId={mockYoutubeVideoId} />);

      mockSegments.forEach((segment) => {
        expect(screen.getByText(segment.text)).toBeInTheDocument();
      });
    });
  });
});
