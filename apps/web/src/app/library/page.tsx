'use client';

import { Suspense, useCallback, useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import { Pagination } from '@/components/common/Pagination';
import { FilterSidebar, VideoCard } from '@/components/library';
import { SelectionBar } from '@/components/library/SelectionBar';
import type { FilterState } from '@/components/library';
import type { VideoCard as VideoCardType, ProcessingStatusFilter } from '@/services/api';
import { libraryApi } from '@/services/api';
import { VideoSelectionProvider, useVideoSelection } from '@/contexts/VideoSelectionContext';
import { CheckIcon, XMarkIcon } from '@heroicons/react/20/solid';

const DEFAULT_FILTERS: FilterState = {
  channelId: null,
  fromDate: null,
  toDate: null,
  facets: [],
  status: null,
  search: '',
  sortBy: 'publishDate',
  sortOrder: 'desc',
};

const PAGE_SIZE = 12;

// Polling intervals for updates
const FAST_POLLING_INTERVAL = 5000;  // 5 seconds when videos are processing
const SLOW_POLLING_INTERVAL = 30000; // 30 seconds to check for new videos

// Valid processing status filter values
const VALID_STATUSES: ProcessingStatusFilter[] = ['pending', 'processing', 'completed', 'failed', 'rate_limited'];

/**
 * Toggle button for entering/exiting selection mode
 */
function SelectionModeToggle() {
  const { selectionMode, enterSelectionMode, exitSelectionMode, selectedVideos } = useVideoSelection();

  if (selectionMode) {
    return (
      <button
        onClick={exitSelectionMode}
        className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-lg border-2 border-red-500 bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-500/20 transition-colors"
      >
        <XMarkIcon className="w-4 h-4" />
        Exit selection
        {selectedVideos.length > 0 && (
          <span className="ml-1 px-1.5 py-0.5 text-xs font-bold rounded-full bg-red-500 text-white">
            {selectedVideos.length}
          </span>
        )}
      </button>
    );
  }

  return (
    <button
      onClick={enterSelectionMode}
      className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
    >
      <CheckIcon className="w-4 h-4" />
      Select videos
    </button>
  );
}

/**
 * Inner component that reads URL search params.
 * Separated to keep the Suspense boundary tight around useSearchParams.
 */
function LibraryContentWithParams() {
  const searchParams = useSearchParams();
  const statusFromUrl = searchParams.get('status');

  // Validate status from URL is a valid ProcessingStatusFilter
  const validStatus = statusFromUrl && VALID_STATUSES.includes(statusFromUrl as ProcessingStatusFilter)
    ? (statusFromUrl as ProcessingStatusFilter)
    : null;

  return <LibraryContent initialStatus={validStatus} />;
}

/**
 * Library page content that displays videos
 */
function LibraryContent({ initialStatus }: { initialStatus: ProcessingStatusFilter | null }) {

  const [filters, setFilters] = useState<FilterState>(() => ({
    ...DEFAULT_FILTERS,
    status: initialStatus,
  }));
  const [videos, setVideos] = useState<VideoCardType[]>([]);
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  /**
   * Check if any videos need status updates (pending, processing, or rate_limited)
   */
  const hasVideosNeedingUpdates = useCallback((videoList: VideoCardType[]): boolean => {
    return videoList.some(
      (video) => video.processing_status === 'pending' ||
                 video.processing_status === 'processing' ||
                 video.processing_status === 'rate_limited'
    );
  }, []);

  const fetchVideos = useCallback(async (isPolling = false) => {
    try {
      // Only show loading spinner on initial load, not during polling
      if (!isPolling) {
        setLoading(true);
      }
      setError(null);

      const response = await libraryApi.listVideos({
        channel_id: filters.channelId || undefined,
        from_date: filters.fromDate || undefined,
        to_date: filters.toDate || undefined,
        facets: filters.facets.length > 0 ? filters.facets : undefined,
        status: filters.status || undefined,
        search: filters.search || undefined,
        sort_by: filters.sortBy,
        sort_order: filters.sortOrder,
        page,
        page_size: PAGE_SIZE,
      });

      setVideos(response.videos);
      setTotalCount(response.total_count);
    } catch (err) {
      console.error('Failed to fetch videos:', err);
      setError('Failed to load videos. Please try again.');
    } finally {
      if (!isPolling) {
        setLoading(false);
      }
    }
  }, [filters, page]);

  // Initial fetch and refetch when filters/page change
  useEffect(() => {
    fetchVideos(false);
  }, [fetchVideos]);

  // Set up polling for updates (fast when processing, slow for new videos)
  useEffect(() => {
    // Clear any existing polling interval
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }

    // Use faster polling when videos are processing, slower polling otherwise
    const interval = hasVideosNeedingUpdates(videos)
      ? FAST_POLLING_INTERVAL
      : SLOW_POLLING_INTERVAL;

    pollingIntervalRef.current = setInterval(() => {
      fetchVideos(true);
    }, interval);

    // Cleanup on unmount or when videos change
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [videos, hasVideosNeedingUpdates, fetchVideos]);

  // Reset to page 1 when filters change
  const handleFilterChange = (newFilters: Partial<FilterState>) => {
    setFilters((prev) => ({ ...prev, ...newFilters }));
    setPage(1);
  };

  const handleClearFilters = () => {
    setFilters(DEFAULT_FILTERS);
    setPage(1);
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] bg-gray-100 dark:bg-[#0f0f0f]">
      {/* Main content - full width like YouTube */}
      <main className="px-4 py-3 sm:px-6 lg:px-6 xl:px-6">
        {/* Minimal header - YouTube style */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <SelectionModeToggle />
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {loading ? (
                <span className="animate-pulse">Loading...</span>
              ) : (
                <>{totalCount} videos</>
              )}
            </span>
          </div>
        </div>

        <div className="flex flex-col gap-6 lg:flex-row">
          {/* Sidebar */}
          <FilterSidebar
            filters={filters}
            onFilterChange={handleFilterChange}
            onClearFilters={handleClearFilters}
          />

          {/* Video grid */}
          <div className="flex-1">
            {/* Error state */}
            {error && (
              <div className="mb-4 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-4">
                <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
                <button
                  type="button"
                  onClick={() => fetchVideos()}
                  className="mt-2 text-sm font-medium text-red-700 dark:text-red-400 hover:text-red-600"
                >
                  Try again
                </button>
              </div>
            )}

            {/* Loading state */}
            {loading && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div
                    key={i}
                    className="rounded-xl border-2 border-gray-200/60 dark:border-gray-700/60 bg-white dark:bg-[#1a1a1a] overflow-hidden"
                  >
                    <div className="aspect-video animate-pulse bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200 dark:from-gray-800 dark:via-gray-700 dark:to-gray-800 bg-[length:200%_100%] animate-shimmer" />
                    <div className="p-3 space-y-2">
                      <div className="h-4 w-full animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                      <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                      <div className="h-3 w-1/2 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Empty state */}
            {!loading && !error && videos.length === 0 && (
              <div className="rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800/50 p-12 text-center shadow-sm">
                <div className="mx-auto w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center mb-4">
                  <svg className="w-8 h-8 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                  No videos found
                </h3>
                <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">
                  Try adjusting your filters or search query.
                </p>
                {(filters.channelId ||
                  filters.fromDate ||
                  filters.toDate ||
                  filters.facets.length > 0 ||
                  filters.status ||
                  filters.search) && (
                  <button
                    type="button"
                    onClick={handleClearFilters}
                    className="mt-4 inline-flex items-center rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 transition-colors"
                  >
                    Clear all filters
                  </button>
                )}
              </div>
            )}

            {/* Video grid - 4 columns like YouTube */}
            {!loading && !error && videos.length > 0 && (
              <>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {videos.map((video) => (
                    <VideoCard key={video.video_id} video={video} />
                  ))}
                </div>

                {/* Pagination */}
                <Pagination
                  page={page}
                  pageSize={PAGE_SIZE}
                  totalCount={totalCount}
                  onPageChange={setPage}
                  className="mt-8"
                />
              </>
            )}
          </div>
        </div>
      </main>

      {/* Floating selection bar */}
      <SelectionBar />
    </div>
  );
}

/**
 * Library page wrapper with Suspense boundary for useSearchParams
 * and VideoSelectionProvider for selection state
 */
export default function LibraryPage() {
  return (
    <VideoSelectionProvider>
      <Suspense fallback={
        <div className="min-h-screen bg-gray-50 flex items-center justify-center">
          <div className="text-gray-500">Loading...</div>
        </div>
      }>
        <LibraryContentWithParams />
      </Suspense>
    </VideoSelectionProvider>
  );
}
