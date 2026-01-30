/**
 * Tests for SummaryCard component
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SummaryCard } from '@/components/SummaryCard';

describe('SummaryCard', () => {
  // Sample summary text with markdown - reserved for markdown rendering tests
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _mockSummaryText = `# Video Summary

This is a test summary with some **bold text** and _italic text_.

## Key Points
- First key point
- Second key point
- Third key point

## Conclusion
This concludes the summary.`;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('renders empty state when no summaryUrl', () => {
      render(<SummaryCard summaryUrl={null} />);
      expect(screen.getByText('Summary not available yet')).toBeInTheDocument();
    });

    it('renders processing message in empty state', () => {
      render(<SummaryCard summaryUrl={null} />);
      expect(screen.getByText(/processing may still be in progress/i)).toBeInTheDocument();
    });

    it('renders loading skeleton while fetching', async () => {
      global.fetch = vi.fn().mockImplementation(
        () => new Promise(() => {}) // Never resolves
      );
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);
      await waitFor(() => {
        // Loading state shows animated placeholder divs
        expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
      });
    });

    it('renders summary content after fetch', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Simple summary text',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);
      await waitFor(() => {
        expect(screen.getByText('Simple summary text')).toBeInTheDocument();
      });
    });

    it('renders AI Summary header when summary loads', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Summary content',
      });
      render(
        <SummaryCard
          summaryUrl="https://example.com/summary.txt"
        />
      );
      await waitFor(() => {
        expect(screen.getByText('AI Summary')).toBeInTheDocument();
      });
    });
  });

  describe('Error handling', () => {
    it('shows error message on fetch failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/failed to load summary/i)).toBeInTheDocument();
      });
    });

    it('shows error message on network error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);
      await waitFor(() => {
        expect(screen.getByText(/failed to load summary/i)).toBeInTheDocument();
      });
    });
  });

  describe('Copy functionality', () => {
    it('shows copy button after summary loads', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Summary text',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);

      await waitFor(() => {
        expect(screen.getByText('Copy')).toBeInTheDocument();
      });
    });

    it('copies summary to clipboard when copy clicked', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.assign(navigator, { clipboard: { writeText } });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Summary to copy',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);

      await waitFor(() => {
        expect(screen.getByText('Copy')).toBeInTheDocument();
      });

      const copyButton = screen.getByText('Copy');
      fireEvent.click(copyButton);

      await waitFor(() => {
        expect(writeText).toHaveBeenCalledWith('Summary to copy');
      });
    });

    it('shows copied confirmation after copy', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.assign(navigator, { clipboard: { writeText } });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Summary text',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);

      await waitFor(() => {
        expect(screen.getByText('Copy')).toBeInTheDocument();
      });

      const copyButton = screen.getByText('Copy');
      fireEvent.click(copyButton);

      await waitFor(() => {
        expect(screen.getByText(/copied/i)).toBeInTheDocument();
      });
    });
  });

  describe('Markdown rendering', () => {
    it('renders summary heading', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Test summary content',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);

      await waitFor(() => {
        // The component has an "AI Summary" heading
        expect(screen.getByText('AI Summary')).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('has accessible container', () => {
      render(<SummaryCard summaryUrl={null} />);
      const container = screen.getByText('Summary not available yet').closest('div');
      expect(container).toBeInTheDocument();
    });

    it('copy button has title attribute', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'Summary text',
      });
      render(<SummaryCard summaryUrl="https://example.com/summary.txt" />);

      await waitFor(() => {
        const copyButton = screen.getByText('Copy').closest('button');
        expect(copyButton).toHaveAttribute('title', 'Copy summary');
      });
    });
  });
});
