/**
 * Loading skeleton components for async data fetches.
 * Provides visual feedback while content is loading.
 */

import React from 'react';

// Base skeleton component with animation
export function Skeleton({ className = '' }: { className?: string }) {
  return (
    <div
      className={`animate-pulse bg-gray-200 dark:bg-gray-700 rounded ${className}`}
      aria-hidden="true"
    />
  );
}

// ============================================================================
// VideoCardSkeleton - For library grid
// ============================================================================

export function VideoCardSkeleton() {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm overflow-hidden">
      {/* Thumbnail skeleton */}
      <Skeleton className="w-full h-40" />
      
      <div className="p-4">
        {/* Title skeleton (2 lines) */}
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-3/4 mb-3" />
        
        {/* Channel name */}
        <Skeleton className="h-3 w-1/2 mb-2" />
        
        {/* Meta info */}
        <div className="flex gap-2">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-3 w-20" />
        </div>
      </div>
    </div>
  );
}

export function VideoGridSkeleton({ count = 8 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <VideoCardSkeleton key={i} />
      ))}
    </div>
  );
}

// ============================================================================
// JobProgressSkeleton - For job status
// ============================================================================

export function JobProgressSkeleton() {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-6 w-20 rounded-full" />
      </div>
      
      {/* Progress bar */}
      <Skeleton className="h-2 w-full rounded-full mb-4" />
      
      {/* Steps */}
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <Skeleton className="h-6 w-6 rounded-full" />
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-3 w-16 ml-auto" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// TableRowSkeleton - For table views (batches, dead-letter)
// ============================================================================

export function TableRowSkeleton({ columns = 5 }: { columns?: number }) {
  return (
    <tr className="border-b border-gray-200 dark:border-gray-700">
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <Skeleton className="h-4 w-full" />
        </td>
      ))}
    </tr>
  );
}

export function TableSkeleton({ rows = 5, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            {Array.from({ length: columns }).map((_, i) => (
              <th key={i} className="px-4 py-3 text-left">
                <Skeleton className="h-4 w-20" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <TableRowSkeleton key={i} columns={columns} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ============================================================================
// MessageSkeleton - For copilot responses
// ============================================================================

export function MessageSkeleton() {
  return (
    <div className="flex gap-3 p-4">
      {/* Avatar */}
      <Skeleton className="h-8 w-8 rounded-full flex-shrink-0" />
      
      <div className="flex-1 space-y-2">
        {/* Message lines */}
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-5/6" />
        <Skeleton className="h-4 w-4/6" />
        
        {/* Citation cards */}
        <div className="flex gap-2 mt-3">
          <Skeleton className="h-20 w-32 rounded-md" />
          <Skeleton className="h-20 w-32 rounded-md" />
        </div>
      </div>
    </div>
  );
}

export function CopilotSidebarSkeleton() {
  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <Skeleton className="h-6 w-32" />
      </div>
      
      {/* Messages */}
      <div className="flex-1 p-4 space-y-4">
        <MessageSkeleton />
        <MessageSkeleton />
      </div>
      
      {/* Input area */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <Skeleton className="h-10 w-full rounded-md" />
      </div>
    </div>
  );
}

// ============================================================================
// VideoDetailSkeleton - For video detail page
// ============================================================================

export function VideoDetailSkeleton() {
  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Video player area */}
      <Skeleton className="w-full aspect-video rounded-lg mb-6" />
      
      {/* Title and meta */}
      <Skeleton className="h-8 w-3/4 mb-2" />
      <Skeleton className="h-4 w-1/3 mb-4" />
      
      {/* Channel info */}
      <div className="flex items-center gap-3 mb-6">
        <Skeleton className="h-10 w-10 rounded-full" />
        <div>
          <Skeleton className="h-4 w-32 mb-1" />
          <Skeleton className="h-3 w-24" />
        </div>
      </div>
      
      {/* Summary section */}
      <div className="mb-6">
        <Skeleton className="h-5 w-24 mb-3" />
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-5/6" />
      </div>
      
      {/* Segments */}
      <div>
        <Skeleton className="h-5 w-24 mb-3" />
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex gap-3 mb-3">
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 flex-1" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// BatchDetailSkeleton - For batch status page
// ============================================================================

export function BatchDetailSkeleton() {
  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <Skeleton className="h-8 w-48 mb-2" />
          <Skeleton className="h-4 w-32" />
        </div>
        <Skeleton className="h-10 w-24 rounded-md" />
      </div>
      
      {/* Progress overview */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6">
        <div className="flex justify-between mb-4">
          <Skeleton className="h-5 w-24" />
          <Skeleton className="h-5 w-16" />
        </div>
        <Skeleton className="h-3 w-full rounded-full" />
      </div>
      
      {/* Video list */}
      <TableSkeleton rows={10} columns={4} />
    </div>
  );
}

export default Skeleton;
