/**
 * Tests for FilterSidebar component
 *
 * These tests verify:
 * - Valid status filter values are accepted
 * - Status filter correctly maps to API enum values
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { FilterSidebar, FilterState } from '@/components/library/FilterSidebar';

// Mock the child components
vi.mock('@/components/library/ChannelFilter', () => ({
  ChannelFilter: ({ onSelect }: { onSelect: (id: string | null) => void }) => (
    <button data-testid="channel-filter" onClick={() => onSelect('channel-1')}>
      Channel Filter
    </button>
  ),
}));

vi.mock('@/components/library/DateRangePicker', () => ({
  DateRangePicker: () => <div data-testid="date-range-picker">Date Range</div>,
}));

vi.mock('@/components/library/FacetChips', () => ({
  FacetChips: () => <div data-testid="facet-chips">Facet Chips</div>,
}));

const defaultFilters: FilterState = {
  channelId: null,
  fromDate: null,
  toDate: null,
  facets: [],
  status: null,
  search: '',
  sortBy: 'publishDate',
  sortOrder: 'desc',
};

describe('FilterSidebar', () => {
  const mockOnFilterChange = vi.fn();
  const mockOnClearFilters = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Status filter', () => {
    it('displays all valid status options', () => {
      render(
        <FilterSidebar
          filters={defaultFilters}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const statusSelect = screen.getByRole('combobox', { name: /status/i });
      expect(statusSelect).toBeInTheDocument();

      // Check all valid status options are present
      const options = statusSelect.querySelectorAll('option');
      const optionValues = Array.from(options).map((opt) => opt.value);

      expect(optionValues).toContain('');  // All Status
      expect(optionValues).toContain('completed');
      expect(optionValues).toContain('processing');
      expect(optionValues).toContain('pending');
      expect(optionValues).toContain('failed');

      // 'ready' should NOT be a valid option
      expect(optionValues).not.toContain('ready');
    });

    it('calls onFilterChange with correct status when completed is selected', () => {
      render(
        <FilterSidebar
          filters={defaultFilters}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const statusSelect = screen.getByRole('combobox', { name: /status/i });
      fireEvent.change(statusSelect, { target: { value: 'completed' } });

      expect(mockOnFilterChange).toHaveBeenCalledWith({ status: 'completed' });
    });

    it('calls onFilterChange with null when All Status is selected', () => {
      render(
        <FilterSidebar
          filters={{ ...defaultFilters, status: 'completed' }}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const statusSelect = screen.getByRole('combobox', { name: /status/i });
      fireEvent.change(statusSelect, { target: { value: '' } });

      expect(mockOnFilterChange).toHaveBeenCalledWith({ status: null });
    });

    it('displays correct selected status value', () => {
      render(
        <FilterSidebar
          filters={{ ...defaultFilters, status: 'completed' }}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const statusSelect = screen.getByRole('combobox', { name: /status/i }) as HTMLSelectElement;
      expect(statusSelect.value).toBe('completed');
    });
  });

  describe('Status filter values match API enum', () => {
    /**
     * CRITICAL: These tests ensure the frontend status filter values
     * match what the API expects. The API uses ProcessingStatusFilter enum
     * with values: 'pending', 'processing', 'completed', 'failed'
     *
     * Any mismatch (like using 'ready' instead of 'completed') will cause
     * API errors when filtering.
     */

    const validApiStatuses = ['pending', 'processing', 'completed', 'failed'];

    it.each(validApiStatuses)(
      'status "%s" is a valid filter option',
      (status) => {
        render(
          <FilterSidebar
            filters={defaultFilters}
            onFilterChange={mockOnFilterChange}
            onClearFilters={mockOnClearFilters}
          />
        );

        const statusSelect = screen.getByRole('combobox', { name: /status/i });
        const options = statusSelect.querySelectorAll('option');
        const optionValues = Array.from(options).map((opt) => opt.value);

        expect(optionValues).toContain(status);
      }
    );

    it('does not include invalid status values like "ready"', () => {
      render(
        <FilterSidebar
          filters={defaultFilters}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const statusSelect = screen.getByRole('combobox', { name: /status/i });
      const options = statusSelect.querySelectorAll('option');
      const optionValues = Array.from(options).map((opt) => opt.value);

      // These are NOT valid API status values
      expect(optionValues).not.toContain('ready');
      expect(optionValues).not.toContain('success');
      expect(optionValues).not.toContain('done');
      expect(optionValues).not.toContain('error');
    });
  });

  describe('Clear filters', () => {
    it('calls onClearFilters when clear button is clicked', () => {
      render(
        <FilterSidebar
          filters={{ ...defaultFilters, status: 'completed', search: 'test' }}
          onFilterChange={mockOnFilterChange}
          onClearFilters={mockOnClearFilters}
        />
      );

      const clearButton = screen.getByRole('button', { name: /clear/i });
      fireEvent.click(clearButton);

      expect(mockOnClearFilters).toHaveBeenCalled();
    });
  });
});
