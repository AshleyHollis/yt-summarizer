'use client';

import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/24/outline';
import type { ProcessingStatusFilter, SortField, SortOrder } from '@/services/api';
import { ChannelFilter } from './ChannelFilter';
import { DateRangePicker } from './DateRangePicker';
import { FacetChips } from './FacetChips';

export interface FilterState {
  channelId: string | null;
  fromDate: string | null;
  toDate: string | null;
  facets: string[];
  status: ProcessingStatusFilter | null;
  search: string;
  sortBy: SortField;
  sortOrder: SortOrder;
}

interface FilterSidebarProps {
  filters: FilterState;
  onFilterChange: (filters: Partial<FilterState>) => void;
  onClearFilters: () => void;
}

const statusOptions: { value: ProcessingStatusFilter | ''; label: string }[] = [
  { value: '', label: 'All Status' },
  { value: 'completed', label: 'Completed' },
  { value: 'processing', label: 'Processing' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed', label: 'Failed' },
];

const sortOptions: { value: SortField; label: string }[] = [
  { value: 'publishDate', label: 'Publish Date' },
  { value: 'title', label: 'Title' },
  { value: 'createdAt', label: 'Date Added' },
];

/**
 * Filter sidebar component for the library page
 */
export function FilterSidebar({
  filters,
  onFilterChange,
  onClearFilters,
}: FilterSidebarProps) {
  const hasActiveFilters =
    filters.channelId ||
    filters.fromDate ||
    filters.toDate ||
    filters.facets.length > 0 ||
    filters.status ||
    filters.search;

  return (
    <aside className="w-full lg:w-72 shrink-0">
      <div className="sticky top-4 rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Filters</h2>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={onClearFilters}
              className="text-sm text-indigo-600 hover:text-indigo-500"
            >
              Clear all
            </button>
          )}
        </div>

        {/* Search */}
        <div className="mb-4">
          <label
            htmlFor="search"
            className="mb-2 block text-sm font-medium text-gray-700"
          >
            Search
          </label>
          <div className="relative">
            <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              id="search"
              value={filters.search}
              onChange={(e) => onFilterChange({ search: e.target.value })}
              placeholder="Search videos..."
              className="block w-full rounded-md border border-gray-300 py-2 pl-10 pr-10 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            {filters.search && (
              <button
                type="button"
                onClick={() => onFilterChange({ search: '' })}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        {/* Channel filter */}
        <ChannelFilter
          selectedChannelId={filters.channelId}
          onChannelChange={(channelId) => onFilterChange({ channelId })}
        />

        {/* Date range */}
        <DateRangePicker
          fromDate={filters.fromDate}
          toDate={filters.toDate}
          onFromDateChange={(fromDate) => onFilterChange({ fromDate })}
          onToDateChange={(toDate) => onFilterChange({ toDate })}
        />

        {/* Status filter */}
        <div className="mb-4">
          <label
            htmlFor="status-filter"
            className="mb-2 block text-sm font-medium text-gray-700"
          >
            Status
          </label>
          <select
            id="status-filter"
            value={filters.status || ''}
            onChange={(e) =>
              onFilterChange({
                status: (e.target.value as ProcessingStatusFilter) || null,
              })
            }
            className="block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            {statusOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        {/* Facet chips */}
        <FacetChips
          selectedFacets={filters.facets}
          onFacetToggle={(facetId) => {
            const newFacets = filters.facets.includes(facetId)
              ? filters.facets.filter((id) => id !== facetId)
              : [...filters.facets, facetId];
            onFilterChange({ facets: newFacets });
          }}
          onClearFacets={() => onFilterChange({ facets: [] })}
        />

        {/* Sort options */}
        <div className="mb-4">
          <label
            htmlFor="sort-by"
            className="mb-2 block text-sm font-medium text-gray-700"
          >
            Sort By
          </label>
          <div className="flex gap-2">
            <select
              id="sort-by"
              value={filters.sortBy}
              onChange={(e) =>
                onFilterChange({ sortBy: e.target.value as SortField })
              }
              className="block flex-1 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              {sortOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <select
              id="sort-order"
              value={filters.sortOrder}
              onChange={(e) =>
                onFilterChange({ sortOrder: e.target.value as SortOrder })
              }
              className="block w-24 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="desc">Desc</option>
              <option value="asc">Asc</option>
            </select>
          </div>
        </div>
      </div>
    </aside>
  );
}

export default FilterSidebar;
