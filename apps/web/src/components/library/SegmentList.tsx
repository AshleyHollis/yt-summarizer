'use client';

import { PlayIcon } from '@heroicons/react/24/solid';
import type { Segment } from '@/services/api';

interface SegmentListProps {
  segments: Segment[];
  youtubeVideoId: string;
}

/**
 * Format seconds to MM:SS or HH:MM:SS
 */
function formatTime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  if (hours > 0) {
    return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

/**
 * Segment list component displaying transcript segments with clickable timestamps
 */
export function SegmentList({ segments, youtubeVideoId }: SegmentListProps) {
  if (segments.length === 0) {
    return (
      <div className="rounded-lg border border-gray-200 bg-gray-50 p-8 text-center">
        <p className="text-gray-500">No transcript segments available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {segments.map((segment) => (
        <div
          key={segment.segment_id}
          className="group flex gap-3 rounded-lg border border-gray-200 bg-white p-4 transition-colors hover:border-indigo-200 hover:bg-indigo-50/50"
        >
          {/* Timestamp button */}
          <a
            href={segment.youtube_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-gray-100 px-2.5 py-1.5 text-sm font-medium text-gray-700 transition-colors hover:bg-indigo-100 hover:text-indigo-700 group-hover:bg-indigo-100 group-hover:text-indigo-700"
            title={`Jump to ${formatTime(segment.start_time)} on YouTube`}
          >
            <PlayIcon className="h-3.5 w-3.5" />
            <span>{formatTime(segment.start_time)}</span>
          </a>

          {/* Segment text */}
          <div className="flex-1 min-w-0">
            <p className="text-sm text-gray-700 leading-relaxed">
              {segment.text}
            </p>
            <p className="mt-1 text-xs text-gray-400">
              {formatTime(segment.start_time)} - {formatTime(segment.end_time)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default SegmentList;
