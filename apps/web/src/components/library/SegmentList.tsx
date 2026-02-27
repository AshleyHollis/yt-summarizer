'use client';

import { PlayIcon } from '@heroicons/react/24/solid';
import type { Segment } from '@/services/api';
import { formatDuration } from '@/utils/formatDuration';

interface SegmentListProps {
  segments: Segment[];
  youtubeVideoId: string;
}

/**
 * Segment list component displaying transcript segments with clickable timestamps
 */
export function SegmentList({ segments }: SegmentListProps) {
  if (segments.length === 0) {
    return (
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 p-8 text-center">
        <p className="text-gray-500 dark:text-gray-400">No transcript segments available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {segments.map((segment) => (
        <div
          key={segment.segment_id}
          className="group flex gap-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/50 p-4 transition-all hover:border-red-300 dark:hover:border-red-800 hover:bg-red-50/30 dark:hover:bg-red-900/10 hover:shadow-sm"
        >
          {/* Timestamp button - cleaner design */}
          <a
            href={segment.youtube_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex shrink-0 flex-col items-center justify-center gap-0.5 w-16 h-14 rounded-lg bg-gray-100 dark:bg-gray-700/80 text-gray-600 dark:text-gray-300 transition-all hover:bg-red-500 hover:text-white dark:hover:bg-red-600 group-hover:bg-red-100 dark:group-hover:bg-red-900/40 group-hover:text-red-600 dark:group-hover:text-red-400"
            title={`Watch from ${formatDuration(segment.start_time)} on YouTube`}
          >
            <PlayIcon className="h-4 w-4" />
            <span className="text-xs font-medium tabular-nums">
              {formatDuration(segment.start_time)}
            </span>
          </a>

          {/* Segment text */}
          <div className="flex-1 min-w-0">
            <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed line-clamp-4">
              {segment.text}
            </p>
            <p className="mt-2 text-xs text-gray-400 dark:text-gray-500 tabular-nums">
              {formatDuration(segment.start_time)} – {formatDuration(segment.end_time)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default SegmentList;
