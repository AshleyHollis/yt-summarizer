/**
 * Tests for TranscriptViewer component
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { TranscriptViewer } from '@/components/TranscriptViewer';

describe('TranscriptViewer', () => {
  const mockTranscriptText = 'Hello world. This is a test transcript for the viewer component.';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Empty state', () => {
    it('renders empty state when no transcriptUrl', () => {
      render(<TranscriptViewer transcriptUrl={null} />);
      expect(screen.getByText('Transcript not available yet')).toBeInTheDocument();
    });

    it('shows processing message in empty state', () => {
      render(<TranscriptViewer transcriptUrl={null} />);
      expect(screen.getByText(/processing may still be in progress/i)).toBeInTheDocument();
    });
  });

  describe('Loading state', () => {
    it('shows loading skeleton while fetching', async () => {
      global.fetch = vi.fn().mockImplementation(
        () => new Promise(() => {}) // Never resolves
      );
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        // Loading state shows animated placeholder divs
        expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
      });
    });
  });

  describe('Loaded state', () => {
    it('renders transcript text after fetch', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => mockTranscriptText,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/Hello world/)).toBeInTheDocument();
      });
    });

    it('shows Transcript heading', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => mockTranscriptText,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByText('Transcript')).toBeInTheDocument();
      });
    });

    it('shows word count in footer', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'one two three four five',
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/5 words/i)).toBeInTheDocument();
      });
    });
  });

  describe('Error handling', () => {
    it('shows error message on fetch failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/failed to load transcript/i)).toBeInTheDocument();
      });
    });

    it('shows error message on network error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/failed to load transcript/i)).toBeInTheDocument();
      });
    });
  });

  describe('Search functionality', () => {
    it('shows search input after transcript loads', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => mockTranscriptText,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/search transcript/i)).toBeInTheDocument();
      });
    });

    it('shows match count when searching', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'test test test',
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/search transcript/i)).toBeInTheDocument();
      });

      const searchInput = screen.getByPlaceholderText(/search transcript/i);
      fireEvent.change(searchInput, { target: { value: 'test' } });

      await waitFor(() => {
        expect(screen.getByText(/3 matches/i)).toBeInTheDocument();
      });
    });
  });

  describe('Expand/Collapse', () => {
    it('shows expand button', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => mockTranscriptText,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);

      await waitFor(() => {
        expect(screen.getByText(/expand/i)).toBeInTheDocument();
      });
    });

    it('toggles to Collapse when clicked', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => mockTranscriptText,
      });
      render(<TranscriptViewer transcriptUrl="https://example.com/transcript.txt" />);

      await waitFor(() => {
        expect(screen.getByText(/expand/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText(/expand/i));
      expect(screen.getByText(/collapse/i)).toBeInTheDocument();
    });
  });
});
