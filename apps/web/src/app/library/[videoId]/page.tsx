'use client';

import { useCallback, useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeftIcon,
  ClockIcon,
  PlayIcon,
  TagIcon,
} from '@heroicons/react/24/outline';
import { Pagination } from '@/components/common/Pagination';
import { SegmentList } from '@/components/library';
import type { Segment, VideoDetailResponse } from '@/services/api';
import { libraryApi } from '@/services/api';

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
    month: 'long',
    day: 'numeric',
  });
}

/**
 * Get status badge styles
 */
function getStatusBadge(status: string): { className: string; label: string } {
  switch (status) {
    case 'completed':
      return {
        className: 'bg-green-100 text-green-800',
        label: 'Completed',
      };
    case 'processing':
      return {
        className: 'bg-blue-100 text-blue-800',
        label: 'Processing',
      };
    case 'pending':
      return {
        className: 'bg-yellow-100 text-yellow-800',
        label: 'Pending',
      };
    case 'failed':
      return { className: 'bg-red-100 text-red-800', label: 'Failed' };
    default:
      return { className: 'bg-gray-100 text-gray-800', label: status };
  }
}

const SEGMENTS_PAGE_SIZE = 20;

/**
 * Video detail page with segments and metadata
 */
export default function VideoDetailPage() {
  const params = useParams();
  const videoId = params.videoId as string;

  const [video, setVideo] = useState<VideoDetailResponse | null>(null);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [segmentsPage, setSegmentsPage] = useState(1);
  const [totalSegments, setTotalSegments] = useState(0);
  const [loading, setLoading] = useState(true);
  const [segmentsLoading, setSegmentsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch video detail
  useEffect(() => {
    async function fetchVideo() {
      try {
        setLoading(true);
        setError(null);
        const response = await libraryApi.getVideoDetail(videoId);
        setVideo(response);
        setTotalSegments(response.segment_count);
      } catch (err) {
        console.error('Failed to fetch video:', err);
        setError('Failed to load video. Please try again.');
      } finally {
        setLoading(false);
      }
    }

    if (videoId) {
      fetchVideo();
    }
  }, [videoId]);

  // Fetch segments
  const fetchSegments = useCallback(async () => {
    if (!videoId) return;

    try {
      setSegmentsLoading(true);
      const response = await libraryApi.listSegments(
        videoId,
        segmentsPage,
        SEGMENTS_PAGE_SIZE
      );
      setSegments(response.segments);
      setTotalSegments(response.total_count);
    } catch (err) {
      console.error('Failed to fetch segments:', err);
    } finally {
      setSegmentsLoading(false);
    }
  }, [videoId, segmentsPage]);

  useEffect(() => {
    if (video && video.segment_count > 0) {
      fetchSegments();
    }
  }, [video, fetchSegments]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="h-8 w-48 rounded bg-gray-200" />
            <div className="mt-8 aspect-video w-full rounded-lg bg-gray-200" />
            <div className="mt-6 h-8 w-3/4 rounded bg-gray-200" />
            <div className="mt-4 h-4 w-1/2 rounded bg-gray-200" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !video) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
          <Link
            href="/library"
            className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900"
          >
            <ArrowLeftIcon className="mr-2 h-4 w-4" />
            Back to Library
          </Link>
          <div className="mt-8 rounded-lg border border-red-200 bg-red-50 p-6 text-center">
            <h2 className="text-lg font-medium text-red-800">
              {error || 'Video not found'}
            </h2>
            <Link
              href="/library"
              className="mt-4 inline-flex items-center rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
            >
              Return to Library
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const statusBadge = getStatusBadge(video.processing_status);
  const thumbnailUrl =
    video.thumbnail_url ||
    `https://img.youtube.com/vi/${video.youtube_video_id}/maxresdefault.jpg`;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Back link */}
        <Link
          href="/library"
          className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900"
        >
          <ArrowLeftIcon className="mr-2 h-4 w-4" />
          Back to Library
        </Link>

        {/* Video header */}
        <div className="mt-6 overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
          {/* Thumbnail with play button */}
          <div className="relative aspect-video w-full bg-gray-100">
            <Image
              src={thumbnailUrl}
              alt={video.title}
              fill
              sizes="(max-width: 1024px) 100vw, 1024px"
              className="object-cover"
              priority
            />
            <a
              href={video.youtube_url}
              target="_blank"
              rel="noopener noreferrer"
              className="absolute inset-0 flex items-center justify-center bg-black/20 transition-colors hover:bg-black/30"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-600 text-white shadow-lg transition-transform hover:scale-110">
                <PlayIcon className="h-8 w-8 ml-1" />
              </div>
            </a>
            {/* Status badge */}
            <span
              className={`absolute top-4 right-4 rounded-full px-3 py-1 text-sm font-medium ${statusBadge.className}`}
            >
              {statusBadge.label}
            </span>
          </div>

          {/* Video info */}
          <div className="p-6">
            <h1 className="text-2xl font-bold text-gray-900">{video.title}</h1>

            {/* Channel and metadata */}
            <div className="mt-4 flex flex-wrap items-center gap-4 text-sm text-gray-500">
              <Link
                href={`/library?channelId=${video.channel.channel_id}`}
                className="font-medium text-indigo-600 hover:text-indigo-500"
              >
                {video.channel.name}
              </Link>
              <span className="flex items-center gap-1">
                <ClockIcon className="h-4 w-4" />
                {formatDuration(video.duration)}
              </span>
              <span>Published {formatDate(video.publish_date)}</span>
            </div>

            {/* Facets */}
            {video.facets.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {video.facets.map((facet) => (
                  <span
                    key={facet.facet_id}
                    className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-3 py-1 text-sm text-gray-700"
                  >
                    <TagIcon className="h-3.5 w-3.5" />
                    {facet.name}
                  </span>
                ))}
              </div>
            )}

            {/* Description */}
            {video.description && (
              <div className="mt-6">
                <h2 className="text-sm font-medium text-gray-700">
                  Description
                </h2>
                <p className="mt-2 whitespace-pre-wrap text-sm text-gray-600">
                  {video.description}
                </p>
              </div>
            )}

            {/* Summary */}
            {video.summary && (
              <div className="mt-6 rounded-lg bg-indigo-50 p-4">
                <h2 className="text-sm font-medium text-indigo-900">
                  AI Summary
                </h2>
                <p className="mt-2 whitespace-pre-wrap text-sm text-indigo-800">
                  {video.summary}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Transcript segments */}
        {video.segment_count > 0 && (
          <div className="mt-8">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-xl font-bold text-gray-900">
                Transcript Segments
              </h2>
              <span className="text-sm text-gray-500">
                {totalSegments} segments
              </span>
            </div>

            {segmentsLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div
                    key={i}
                    className="h-20 animate-pulse rounded-lg bg-gray-200"
                  />
                ))}
              </div>
            ) : (
              <>
                <SegmentList
                  segments={segments}
                  youtubeVideoId={video.youtube_video_id}
                />
                <Pagination
                  page={segmentsPage}
                  pageSize={SEGMENTS_PAGE_SIZE}
                  totalCount={totalSegments}
                  onPageChange={setSegmentsPage}
                  className="mt-6"
                />
              </>
            )}
          </div>
        )}

        {/* Stats */}
        <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-lg border border-gray-200 bg-white p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {video.segment_count}
            </p>
            <p className="text-sm text-gray-500">Segments</p>
          </div>
          <div className="rounded-lg border border-gray-200 bg-white p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {video.relationship_count}
            </p>
            <p className="text-sm text-gray-500">Related Videos</p>
          </div>
          <div className="rounded-lg border border-gray-200 bg-white p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {video.facets.length}
            </p>
            <p className="text-sm text-gray-500">Tags</p>
          </div>
          <div className="rounded-lg border border-gray-200 bg-white p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {formatDuration(video.duration)}
            </p>
            <p className="text-sm text-gray-500">Duration</p>
          </div>
        </div>
      </div>
    </div>
  );
}
