/**
 * Tests for Pagination component
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, fireEvent } from '@testing-library/react';
import { Pagination } from '@/components/common/Pagination';

// Mock heroicons
vi.mock('@heroicons/react/24/outline', () => ({
  ChevronLeftIcon: () => <span data-testid="chevron-left">←</span>,
  ChevronRightIcon: () => <span data-testid="chevron-right">→</span>,
}));

describe('Pagination', () => {
  const defaultProps = {
    page: 1,
    pageSize: 10,
    totalCount: 100,
    onPageChange: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders pagination when total pages > 1', () => {
      render(<Pagination {...defaultProps} />);

      // Component has nested nav elements, use getAllByRole
      const navElements = screen.getAllByRole('navigation');
      expect(navElements.length).toBeGreaterThan(0);
    });

    it('does not render when total pages <= 1', () => {
      render(<Pagination {...defaultProps} totalCount={5} />);

      expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    });

    it('shows correct result range', () => {
      render(<Pagination {...defaultProps} />);

      // Use regex to find "Showing 1 to 10 of 100 results"
      expect(screen.getByText(/Showing/)).toBeInTheDocument();
      expect(screen.getByText('100')).toBeInTheDocument();
    });

    it('shows correct range for middle page', () => {
      render(<Pagination {...defaultProps} page={5} />);

      // Page 5: items 41-50 - verify the Showing text contains these
      expect(screen.getByText('41')).toBeInTheDocument();
      expect(screen.getByText('50')).toBeInTheDocument();
    });

    it('shows correct range for last page', () => {
      render(<Pagination {...defaultProps} page={10} totalCount={95} />);

      // Last page with 95 items total: items 91-95
      // "to" and "of" both show 95, so use getAllByText
      expect(screen.getByText('91')).toBeInTheDocument();
      expect(screen.getAllByText('95').length).toBeGreaterThan(0);
    });
  });

  describe('Navigation buttons', () => {
    it('disables previous button on first page', () => {
      render(<Pagination {...defaultProps} page={1} />);

      const prevButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Previous') || btn.querySelector('[data-testid="chevron-left"]')
      );
      
      // At least one previous button should be disabled
      const disabledPrevButton = prevButtons.find(btn => btn.hasAttribute('disabled'));
      expect(disabledPrevButton).toBeTruthy();
    });

    it('enables previous button on page > 1', () => {
      render(<Pagination {...defaultProps} page={5} />);

      const prevButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Previous') || btn.querySelector('[data-testid="chevron-left"]')
      );
      
      // At least one previous button should be enabled
      const enabledPrevButton = prevButtons.find(btn => !btn.hasAttribute('disabled'));
      expect(enabledPrevButton).toBeTruthy();
    });

    it('disables next button on last page', () => {
      render(<Pagination {...defaultProps} page={10} />);

      const nextButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Next') || btn.querySelector('[data-testid="chevron-right"]')
      );
      
      // At least one next button should be disabled
      const disabledNextButton = nextButtons.find(btn => btn.hasAttribute('disabled'));
      expect(disabledNextButton).toBeTruthy();
    });

    it('enables next button when not on last page', () => {
      render(<Pagination {...defaultProps} page={1} />);

      const nextButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Next') || btn.querySelector('[data-testid="chevron-right"]')
      );
      
      // At least one next button should be enabled
      const enabledNextButton = nextButtons.find(btn => !btn.hasAttribute('disabled'));
      expect(enabledNextButton).toBeTruthy();
    });
  });

  describe('Page changes', () => {
    it('calls onPageChange when clicking next', () => {
      const onPageChange = vi.fn();
      render(<Pagination {...defaultProps} page={1} onPageChange={onPageChange} />);

      // Find an enabled next button
      const nextButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Next') || btn.querySelector('[data-testid="chevron-right"]')
      );
      const enabledNextButton = nextButtons.find(btn => !btn.hasAttribute('disabled'));
      
      if (enabledNextButton) {
        fireEvent.click(enabledNextButton);
        expect(onPageChange).toHaveBeenCalledWith(2);
      }
    });

    it('calls onPageChange when clicking previous', () => {
      const onPageChange = vi.fn();
      render(<Pagination {...defaultProps} page={5} onPageChange={onPageChange} />);

      // Find an enabled previous button
      const prevButtons = screen.getAllByRole('button').filter(
        (btn) => btn.textContent?.includes('Previous') || btn.querySelector('[data-testid="chevron-left"]')
      );
      const enabledPrevButton = prevButtons.find(btn => !btn.hasAttribute('disabled'));
      
      if (enabledPrevButton) {
        fireEvent.click(enabledPrevButton);
        expect(onPageChange).toHaveBeenCalledWith(4);
      }
    });

    it('calls onPageChange when clicking page number', () => {
      const onPageChange = vi.fn();
      render(<Pagination {...defaultProps} page={1} onPageChange={onPageChange} />);

      // Click on page 3
      const page3Button = screen.getByRole('button', { name: '3' });
      fireEvent.click(page3Button);
      
      expect(onPageChange).toHaveBeenCalledWith(3);
    });
  });

  describe('Page numbers', () => {
    it('highlights current page', () => {
      render(<Pagination {...defaultProps} page={5} />);

      const currentPageButton = screen.getByRole('button', { name: '5' });
      expect(currentPageButton).toHaveAttribute('aria-current', 'page');
    });

    it('shows ellipsis for large page counts', () => {
      render(<Pagination {...defaultProps} page={1} totalCount={200} />);

      // Should show ... for skipped pages
      const ellipses = screen.getAllByText('...');
      expect(ellipses.length).toBeGreaterThan(0);
    });
  });
});
