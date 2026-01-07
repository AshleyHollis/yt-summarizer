'use client';

import Image from 'next/image';
import Link from 'next/link';
import type { VideoCard as VideoCardType } from '@/services/api';
import { useVideoSelection, toSelectedVideo } from '@/contexts/VideoSelectionContext';
import { formatDuration } from '@/utils/formatDuration';

interface VideoCardProps {
  video: VideoCardType;
}

/**
 * Format date to relative time (YouTube-style)
 */
function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  const diffWeeks = Math.floor(diffDays / 7);
  const diffMonths = Math.floor(diffDays / 30);
  const diffYears = Math.floor(diffDays / 365);

  if (diffYears > 0) return diffYears === 1 ? '1 year ago' : `${diffYears} years ago`;
  if (diffMonths > 0) return diffMonths === 1 ? '1 month ago' : `${diffMonths} months ago`;
  if (diffWeeks > 0) return diffWeeks === 1 ? '1 week ago' : `${diffWeeks} weeks ago`;
  if (diffDays > 0) return diffDays === 1 ? '1 day ago' : `${diffDays} days ago`;
  if (diffHours > 0) return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
  if (diffMins > 0) return diffMins === 1 ? '1 minute ago' : `${diffMins} minutes ago`;
  return 'Just now';
}

/**
 * Get status badge color
 */
function getStatusBadgeClass(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
    case 'processing':
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300';
    case 'pending':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300';
    case 'rate_limited':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300';
    case 'failed':
      return 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300';
    default:
      return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
  }
}

/**
 * Get display label for status
 */
function getStatusLabel(status: string): string {
  switch (status) {
    case 'rate_limited':
      return 'Rate Limited';
    default:
      return status;
  }
}

/**
 * Video card component for library grid display
 * Supports selection mode for multi-video chat
 */
export function VideoCard({ video }: VideoCardProps) {
  const { selectionMode, isSelected, toggleSelection } = useVideoSelection();
  const selected = isSelected(video.video_id);
  
  const thumbnailUrl =
    video.thumbnail_url ||
    `https://img.youtube.com/vi/${video.youtube_video_id}/mqdefault.jpg`;

  const handleClick = (e: React.MouseEvent) => {
    if (selectionMode) {
      e.preventDefault();
      toggleSelection(toSelectedVideo(video));
    }
  };

  const handleCheckboxClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    toggleSelection(toSelectedVideo(video));
  };

  return (
    <Link
      href={`/library/${video.video_id}`}
      onClick={handleClick}
      className={`group relative flex flex-col overflow-hidden rounded-xl border-2 bg-white dark:bg-[#1a1a1a] shadow-sm transition-all duration-150 hover:bg-gray-50 dark:hover:bg-[#252525] ${
        selected 
          ? 'border-red-500 dark:border-red-500 ring-2 ring-red-500/20' 
          : 'border-gray-200/60 dark:border-gray-700/60'
      } ${selectionMode ? 'cursor-pointer' : ''}`}
    >
      {/* Selection checkbox - visible in selection mode or when selected */}
      {(selectionMode || selected) && (
        <button
          onClick={handleCheckboxClick}
          className={`absolute top-2 right-2 z-20 w-6 h-6 rounded-md border-2 flex items-center justify-center transition-all duration-200 ${
            selected
              ? 'bg-red-500 border-red-500 text-white'
              : 'bg-white/90 dark:bg-gray-900/90 border-gray-300 dark:border-gray-600 hover:border-red-400'
          }`}
        >
          {selected && (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
            </svg>
          )}
        </button>
      )}

      {/* Thumbnail */}
      <div className="relative aspect-video w-full overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200 dark:from-gray-800 dark:to-gray-900">
        <Image
          src={thumbnailUrl}
          alt={video.title}
          fill
          sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 25vw"
          className="object-cover transition-transform duration-300 group-hover:scale-105"
        />
        {/* Duration badge - bottom right */}
        <div className="absolute bottom-2 right-2 rounded-md bg-black/80 backdrop-blur-sm px-1 py-0.5 text-xs font-medium text-white">
          {formatDuration(video.duration)}
        </div>
      </div>

      {/* Content */}
      <div className="p-3">
        {/* Status badge - only show for non-completed states */}
        {video.processing_status !== 'completed' && (
          <span
            className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold mb-1 ${getStatusBadgeClass(
              video.processing_status
            )}`}
          >
            {getStatusLabel(video.processing_status)}
          </span>
        )}
        
        {/* Title - with tooltip for full text */}
        <h3 
          className="line-clamp-2 text-sm font-semibold text-gray-900 dark:text-gray-100 transition-colors group-hover:text-red-500"
          title={video.title}
        >
          {video.title}
        </h3>

        {/* Channel name */}
        <p className="mt-1 text-xs text-gray-600 dark:text-gray-400 truncate">
          {video.channel_name}
        </p>

        {/* Relative time */}
        <p className="text-xs text-gray-500 dark:text-gray-500">
          {formatRelativeTime(video.publish_date)}
        </p>
      </div>
    </Link>
  );
}

export default VideoCard;
