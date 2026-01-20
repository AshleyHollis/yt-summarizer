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
export function FilterSidebar({ filters, onFilterChange, onClearFilters }: FilterSidebarProps) {
  const hasActiveFilters =
    filters.channelId ||
    filters.fromDate ||
    filters.toDate ||
    filters.facets.length > 0 ||
    filters.status ||
    filters.search;

  return (
    <aside className="w-full lg:w-80 shrink-0">
      <div className="sticky top-20 rounded-2xl border border-gray-300 dark:border-gray-700/60 bg-white dark:bg-[#1a1a1a]/80 backdrop-blur-sm p-5 shadow-md dark:shadow-black/20">
        {/* Header */}
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-slate-100 to-gray-200 dark:from-gray-700 dark:to-gray-800 flex items-center justify-center">
              <svg
                className="w-4 h-4 text-slate-600 dark:text-gray-300"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
                />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">Filters</h2>
          </div>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={onClearFilters}
              className="text-xs font-medium text-red-500 hover:text-red-400 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>

        {/* Search */}
        <div className="mb-5">
          <label
            htmlFor="search"
            className="mb-2 flex items-center gap-1.5 text-xs font-medium text-gray-600 dark:text-gray-300 uppercase tracking-wider"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            Search
          </label>
          <div className="relative">
            <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400 dark:text-gray-500" />
            <input
              type="text"
              id="search"
              value={filters.search}
              onChange={(e) => onFilterChange({ search: e.target.value })}
              placeholder="Search videos..."
              className="block w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 py-2.5 pl-10 pr-10 text-sm text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30"
            />
            {filters.search && (
              <button
                type="button"
                onClick={() => onFilterChange({ search: '' })}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
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
        <div className="mb-5">
          <label
            htmlFor="status-filter"
            className="mb-2 flex items-center gap-1.5 text-xs font-medium text-gray-600 dark:text-gray-300 uppercase tracking-wider"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
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
            className="block w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30 appearance-none cursor-pointer"
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
            className="mb-2 flex items-center gap-1.5 text-xs font-medium text-gray-600 dark:text-gray-300 uppercase tracking-wider"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12"
              />
            </svg>
            Sort By
          </label>
          <div className="flex gap-2">
            <select
              id="sort-by"
              value={filters.sortBy}
              onChange={(e) => onFilterChange({ sortBy: e.target.value as SortField })}
              className="block flex-1 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30 appearance-none cursor-pointer"
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
              onChange={(e) => onFilterChange({ sortOrder: e.target.value as SortOrder })}
              className="block w-24 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30 appearance-none cursor-pointer"
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
