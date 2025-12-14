import Image from 'next/image';
import Link from 'next/link';
import type { VideoCard as VideoCardType, FacetTag } from '@/services/api';

interface VideoCardProps {
  video: VideoCardType;
}

/**
 * Format duration in seconds to HH:MM:SS or MM:SS
 */
function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

/**
 * Format date to readable string
 */
function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Get status badge color
 */
function getStatusBadgeClass(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-green-100 text-green-800';
    case 'processing':
      return 'bg-blue-100 text-blue-800';
    case 'pending':
      return 'bg-yellow-100 text-yellow-800';
    case 'failed':
      return 'bg-red-100 text-red-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

/**
 * Get facet type badge color
 */
function getFacetBadgeClass(type: string): string {
  switch (type) {
    case 'topic':
      return 'bg-indigo-100 text-indigo-700';
    case 'format':
      return 'bg-purple-100 text-purple-700';
    case 'level':
      return 'bg-orange-100 text-orange-700';
    case 'tool':
      return 'bg-cyan-100 text-cyan-700';
    default:
      return 'bg-gray-100 text-gray-700';
  }
}

/**
 * Video card component for library grid display
 */
export function VideoCard({ video }: VideoCardProps) {
  const thumbnailUrl =
    video.thumbnail_url ||
    `https://img.youtube.com/vi/${video.youtube_video_id}/mqdefault.jpg`;

  return (
    <Link
      href={`/library/${video.video_id}`}
      className="group flex flex-col overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm transition-shadow hover:shadow-md"
    >
      {/* Thumbnail */}
      <div className="relative aspect-video w-full overflow-hidden bg-gray-100">
        <Image
          src={thumbnailUrl}
          alt={video.title}
          fill
          sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"
          className="object-cover transition-transform group-hover:scale-105"
        />
        {/* Duration badge */}
        <div className="absolute bottom-2 right-2 rounded bg-black/80 px-2 py-0.5 text-xs font-medium text-white">
          {formatDuration(video.duration)}
        </div>
        {/* Status badge */}
        <div
          className={`absolute top-2 right-2 rounded px-2 py-0.5 text-xs font-medium ${getStatusBadgeClass(
            video.processing_status
          )}`}
        >
          {video.processing_status}
        </div>
      </div>

      {/* Content */}
      <div className="flex flex-1 flex-col p-4">
        {/* Title */}
        <h3 className="mb-2 line-clamp-2 text-sm font-semibold text-gray-900 group-hover:text-indigo-600">
          {video.title}
        </h3>

        {/* Channel */}
        <p className="mb-2 text-xs text-gray-500">{video.channel_name}</p>

        {/* Metadata */}
        <div className="mb-3 flex items-center gap-3 text-xs text-gray-500">
          <span>{formatDate(video.publish_date)}</span>
          {video.segment_count > 0 && (
            <span>{video.segment_count} segments</span>
          )}
        </div>

        {/* Facets */}
        {video.facets.length > 0 && (
          <div className="mt-auto flex flex-wrap gap-1">
            {video.facets.slice(0, 3).map((facet: FacetTag) => (
              <span
                key={facet.facet_id}
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getFacetBadgeClass(
                  facet.type
                )}`}
              >
                {facet.name}
              </span>
            ))}
            {video.facets.length > 3 && (
              <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
                +{video.facets.length - 3}
              </span>
            )}
          </div>
        )}
      </div>
    </Link>
  );
}

export default VideoCard;
