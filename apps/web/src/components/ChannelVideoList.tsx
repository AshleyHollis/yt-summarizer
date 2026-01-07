'use client';

import { useState, useCallback } from 'react';
import {
  channelApi,
  ChannelVideosResponse,
  ChannelVideo,
  ApiClientError,
} from '@/services/api';
import { formatDuration } from '@/utils/formatDuration';
import { formatDate } from '@/utils/formatDate';

/**
 * Props for ChannelVideoList component
 */
export interface ChannelVideoListProps {
  /** Initial channel response data */
  channelData: ChannelVideosResponse;
  /** Channel URL for loading more */
  channelUrl: string;
  /** Callback when selection changes */
  onSelectionChange?: (selectedIds: string[]) => void;
  /** Custom class name */
  className?: string;
}

/**
 * Component to display and select videos from a channel
 */
export function ChannelVideoList({
  channelData,
  channelUrl,
  onSelectionChange,
  className = '',
}: ChannelVideoListProps) {
  const [videos, setVideos] = useState<ChannelVideo[]>(channelData.videos);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [nextCursor, setNextCursor] = useState<string | null>(channelData.next_cursor);
  const [hasMore, setHasMore] = useState(channelData.has_more);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Toggle selection of a single video
   */
  const toggleSelection = useCallback(
    (videoId: string) => {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        if (next.has(videoId)) {
          next.delete(videoId);
        } else {
          next.add(videoId);
        }
        onSelectionChange?.(Array.from(next));
        return next;
      });
    },
    [onSelectionChange]
  );

  /**
   * Select all videos (that aren't already ingested)
   */
  const selectAll = useCallback(() => {
    const allIds = new Set(
      videos.filter((v) => !v.already_ingested).map((v) => v.youtube_video_id)
    );
    setSelectedIds(allIds);
    onSelectionChange?.(Array.from(allIds));
  }, [videos, onSelectionChange]);

  /**
   * Clear all selections
   */
  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
    onSelectionChange?.([]);
  }, [onSelectionChange]);

  /**
   * Load more videos
   */
  const loadMore = async () => {
    if (!hasMore || !nextCursor || isLoadingMore) return;

    setIsLoadingMore(true);
    setError(null);

    try {
      const response = await channelApi.fetchVideos({
        channel_url: channelUrl,
        cursor: nextCursor,
        limit: 100,
      });
      setVideos((prev) => [...prev, ...response.videos]);
      setNextCursor(response.next_cursor);
      setHasMore(response.has_more);
    } catch (err) {
      console.error('Load more error:', err);
      if (err instanceof ApiClientError) {
        setError(err.message);
      } else {
        setError('Failed to load more videos');
      }
    } finally {
      setIsLoadingMore(false);
    }
  };

  const notIngestedCount = videos.filter((v) => !v.already_ingested).length;
  const selectedCount = selectedIds.size;

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header with channel info and controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {channelData.channel_name}
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {videos.length} videos loaded
            {channelData.total_video_count && ` of ${channelData.total_video_count} total`}
            {notIngestedCount < videos.length && ` (${videos.length - notIngestedCount} already ingested)`}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={selectAll}
            className="px-3 py-1.5 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors dark:bg-red-900 dark:text-red-300"
          >
            Select All ({notIngestedCount})
          </button>
          <button
            onClick={clearSelection}
            className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors dark:bg-gray-700 dark:text-gray-300"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Selection info */}
      {selectedCount > 0 && (
        <div className="bg-red-50 dark:bg-red-900/30 p-3 rounded-lg border border-red-200 dark:border-red-800">
          <p className="text-sm text-red-700 dark:text-red-300">
            <strong>{selectedCount}</strong> video{selectedCount !== 1 ? 's' : ''} selected for ingestion
          </p>
        </div>
      )}

      {/* Video list */}
      <div className="grid gap-2 max-h-96 overflow-y-auto">
        {videos.map((video) => (
          <div
            key={video.youtube_video_id}
            data-testid="video-item"
            className={`flex items-center gap-3 p-3 rounded-lg border transition-colors cursor-pointer ${
              video.already_ingested
                ? 'bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700 opacity-60'
                : selectedIds.has(video.youtube_video_id)
                ? 'bg-red-50 dark:bg-red-900/30 border-red-300 dark:border-red-700'
                : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 hover:border-red-300 dark:hover:border-red-700'
            }`}
            onClick={() => !video.already_ingested && toggleSelection(video.youtube_video_id)}
          >
            {/* Checkbox */}
            <div className="flex-shrink-0">
              {video.already_ingested ? (
                <span className="text-green-600 dark:text-green-400" title="Already ingested">
                  ✓ Already ingested
                </span>
              ) : (
                <input
                  type="checkbox"
                  checked={selectedIds.has(video.youtube_video_id)}
                  onChange={() => toggleSelection(video.youtube_video_id)}
                  className="w-4 h-4 text-red-600 rounded focus:ring-red-500"
                />
              )}
            </div>

            {/* Thumbnail */}
            <div className="flex-shrink-0 w-24 h-14 bg-gray-200 dark:bg-gray-700 rounded overflow-hidden">
              {video.thumbnail_url && (
                <img
                  src={video.thumbnail_url}
                  alt={video.title}
                  className="w-full h-full object-cover"
                  loading="lazy"
                />
              )}
            </div>

            {/* Video info */}
            <div className="flex-1 min-w-0">
              <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {video.title}
              </h4>
              <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400">
                <span>{formatDuration(video.duration)}</span>
                <span>{formatDate(video.publish_date)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Load more button */}
      {hasMore && (
        <div className="flex justify-center pt-2">
          <button
            onClick={loadMore}
            disabled={isLoadingMore}
            className="px-4 py-2 text-sm bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50 transition-colors dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          >
            {isLoadingMore ? 'Loading...' : 'Load More Videos'}
          </button>
        </div>
      )}

      {/* Error message */}
      {error && (
        <p className="text-sm text-red-600 dark:text-red-400 text-center">{error}</p>
      )}
    </div>
  );
}
