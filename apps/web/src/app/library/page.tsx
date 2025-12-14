'use client';

import { useCallback, useEffect, useState } from 'react';
import { Pagination } from '@/components/common/Pagination';
import { FilterSidebar, VideoCard } from '@/components/library';
import type { FilterState } from '@/components/library';
import type { VideoCard as VideoCardType } from '@/services/api';
import { libraryApi } from '@/services/api';

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

/**
 * Library page for browsing and filtering videos
 */
export default function LibraryPage() {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [videos, setVideos] = useState<VideoCardType[]>([]);
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchVideos = useCallback(async () => {
    try {
      setLoading(true);
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
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    fetchVideos();
  }, [fetchVideos]);

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
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold tracking-tight text-gray-900">
            Library
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            Browse and filter your video collection
          </p>
        </div>
      </header>

      {/* Main content */}
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-8 lg:flex-row">
          {/* Sidebar */}
          <FilterSidebar
            filters={filters}
            onFilterChange={handleFilterChange}
            onClearFilters={handleClearFilters}
          />

          {/* Video grid */}
          <div className="flex-1">
            {/* Results count */}
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm text-gray-600">
                {loading ? (
                  'Loading...'
                ) : (
                  <>
                    <span className="font-medium">{totalCount}</span> videos
                    found
                  </>
                )}
              </p>
            </div>

            {/* Error state */}
            {error && (
              <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4">
                <p className="text-sm text-red-700">{error}</p>
                <button
                  type="button"
                  onClick={fetchVideos}
                  className="mt-2 text-sm font-medium text-red-700 hover:text-red-600"
                >
                  Try again
                </button>
              </div>
            )}

            {/* Loading state */}
            {loading && (
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div
                    key={i}
                    className="aspect-video animate-pulse rounded-lg bg-gray-200"
                  />
                ))}
              </div>
            )}

            {/* Empty state */}
            {!loading && !error && videos.length === 0 && (
              <div className="rounded-lg border border-gray-200 bg-white p-12 text-center">
                <h3 className="text-lg font-medium text-gray-900">
                  No videos found
                </h3>
                <p className="mt-2 text-sm text-gray-500">
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
                    className="mt-4 inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
                  >
                    Clear all filters
                  </button>
                )}
              </div>
            )}

            {/* Video grid */}
            {!loading && !error && videos.length > 0 && (
              <>
                <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3">
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
    </div>
  );
}
