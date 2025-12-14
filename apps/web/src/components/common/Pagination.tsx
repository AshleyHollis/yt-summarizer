'use client';

import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/24/outline';

interface PaginationProps {
  page: number;
  pageSize: number;
  totalCount: number;
  onPageChange: (page: number) => void;
  className?: string;
}

/**
 * Pagination component for navigating through paged results
 */
export function Pagination({
  page,
  pageSize,
  totalCount,
  onPageChange,
  className = '',
}: PaginationProps) {
  const totalPages = Math.ceil(totalCount / pageSize);
  const hasPrev = page > 1;
  const hasNext = page < totalPages;

  // Calculate visible page numbers
  const getPageNumbers = (): (number | 'ellipsis')[] => {
    const pages: (number | 'ellipsis')[] = [];
    const showPages = 5;
    const halfShow = Math.floor(showPages / 2);

    let start = Math.max(1, page - halfShow);
    let end = Math.min(totalPages, page + halfShow);

    // Adjust if we're near the beginning or end
    if (page <= halfShow) {
      end = Math.min(totalPages, showPages);
    }
    if (page > totalPages - halfShow) {
      start = Math.max(1, totalPages - showPages + 1);
    }

    // Add first page and ellipsis if needed
    if (start > 1) {
      pages.push(1);
      if (start > 2) {
        pages.push('ellipsis');
      }
    }

    // Add visible page numbers
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }

    // Add ellipsis and last page if needed
    if (end < totalPages) {
      if (end < totalPages - 1) {
        pages.push('ellipsis');
      }
      pages.push(totalPages);
    }

    return pages;
  };

  if (totalPages <= 1) {
    return null;
  }

  const pageNumbers = getPageNumbers();

  return (
    <nav
      className={`flex items-center justify-between border-t border-gray-200 px-4 py-3 sm:px-6 ${className}`}
      aria-label="Pagination"
    >
      {/* Mobile view */}
      <div className="flex flex-1 justify-between sm:hidden">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrev}
          className={`relative inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium ${
            hasPrev
              ? 'bg-white text-gray-700 hover:bg-gray-50'
              : 'bg-gray-100 text-gray-400 cursor-not-allowed'
          }`}
        >
          Previous
        </button>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNext}
          className={`relative ml-3 inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium ${
            hasNext
              ? 'bg-white text-gray-700 hover:bg-gray-50'
              : 'bg-gray-100 text-gray-400 cursor-not-allowed'
          }`}
        >
          Next
        </button>
      </div>

      {/* Desktop view */}
      <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
        <div>
          <p className="text-sm text-gray-700">
            Showing{' '}
            <span className="font-medium">{(page - 1) * pageSize + 1}</span> to{' '}
            <span className="font-medium">
              {Math.min(page * pageSize, totalCount)}
            </span>{' '}
            of <span className="font-medium">{totalCount}</span> results
          </p>
        </div>
        <div>
          <nav
            className="isolate inline-flex -space-x-px rounded-md shadow-sm"
            aria-label="Pagination"
          >
            {/* Previous button */}
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={!hasPrev}
              className={`relative inline-flex items-center rounded-l-md px-2 py-2 ring-1 ring-inset ring-gray-300 ${
                hasPrev
                  ? 'text-gray-400 hover:bg-gray-50 focus:z-20 focus:outline-offset-0'
                  : 'text-gray-300 cursor-not-allowed bg-gray-50'
              }`}
            >
              <span className="sr-only">Previous</span>
              <ChevronLeftIcon className="h-5 w-5" aria-hidden="true" />
            </button>

            {/* Page numbers */}
            {pageNumbers.map((pageNum, index) =>
              pageNum === 'ellipsis' ? (
                <span
                  key={`ellipsis-${index}`}
                  className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300"
                >
                  ...
                </span>
              ) : (
                <button
                  key={pageNum}
                  onClick={() => onPageChange(pageNum)}
                  className={`relative inline-flex items-center px-4 py-2 text-sm font-semibold ${
                    pageNum === page
                      ? 'z-10 bg-indigo-600 text-white focus:z-20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600'
                      : 'text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0'
                  }`}
                  aria-current={pageNum === page ? 'page' : undefined}
                >
                  {pageNum}
                </button>
              )
            )}

            {/* Next button */}
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={!hasNext}
              className={`relative inline-flex items-center rounded-r-md px-2 py-2 ring-1 ring-inset ring-gray-300 ${
                hasNext
                  ? 'text-gray-400 hover:bg-gray-50 focus:z-20 focus:outline-offset-0'
                  : 'text-gray-300 cursor-not-allowed bg-gray-50'
              }`}
            >
              <span className="sr-only">Next</span>
              <ChevronRightIcon className="h-5 w-5" aria-hidden="true" />
            </button>
          </nav>
        </div>
      </div>
    </nav>
  );
}

export default Pagination;
