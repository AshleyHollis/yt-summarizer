'use client';

import { useCallback, useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeftIcon,
  ArrowPathIcon,
  ClockIcon,
  DocumentTextIcon,
  PlayIcon,
  SparklesIcon,
  TagIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline';
import { formatDateLong as formatDate } from '@/utils/formatDate';
import { MarkdownRenderer, DescriptionRenderer } from '@/components/common';
import JobProgress from '@/components/JobProgress';
import ProcessingHistory from '@/components/ProcessingHistory';
import TranscriptViewer from '@/components/TranscriptViewer';
import type { VideoDetailResponse } from '@/services/api';
import { libraryApi, videoApi } from '@/services/api';
import { useVideoContext } from '@/app/providers';
import { formatDuration } from '@/utils/formatDuration';

type TabId = 'summary' | 'description' | 'transcript' | 'history';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}

/**
 * Tab Button component
 */
function TabButton({
  tab,
  isActive,
  onClick,
}: {
  tab: Tab;
  isActive: boolean;
  onClick: () => void;
}) {
  const Icon = tab.icon;
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
        isActive
          ? 'border-red-500 text-red-600 dark:text-red-400'
          : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
      }`}
    >
      <Icon className="h-4 w-4" />
      <span>{tab.label}</span>
      {tab.badge !== undefined && tab.badge > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
          {tab.badge}
        </span>
      )}
    </button>
  );
}

/**
 * Get status badge styles
 */
function getStatusBadge(status: string): { className: string; label: string } {
  switch (status) {
    case 'completed':
      return {
        className: 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300',
        label: 'Completed',
      };
    case 'processing':
      return {
        className: 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300',
        label: 'Processing',
      };
    case 'pending':
      return {
        className: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300',
        label: 'Pending',
      };
    case 'rate_limited':
      return {
        className: 'bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300',
        label: 'Rate Limited - Retrying...',
      };
    case 'failed':
      return {
        className: 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300',
        label: 'Failed',
      };
    default:
      return {
        className: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300',
        label: status,
      };
  }
}

/**
 * Check if video is still processing
 */
function isProcessing(status: string): boolean {
  return [
    'pending',
    'transcribing',
    'summarizing',
    'embedding',
    'building_relationships',
    'rate_limited',
  ].includes(status);
}

/**
 * Video detail page with transcript and metadata
 */
export default function VideoDetailPage() {
  const params = useParams();
  const videoId = params.videoId as string;
  const { setCurrentVideo } = useVideoContext();

  const [video, setVideo] = useState<VideoDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  const [reprocessing, setReprocessing] = useState(false);
  const [reprocessError, setReprocessError] = useState<string | null>(null);

  /**
   * Fetch video detail
   */
  const fetchVideo = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await libraryApi.getVideoDetail(videoId);
      setVideo(response);

      // Set the video context for the copilot to use
      setCurrentVideo({
        videoId: response.video_id,
        title: response.title,
        channelName: response.channel?.name || 'Unknown Channel',
        youtubeVideoId: response.youtube_video_id,
        summary: response.summary ?? undefined,
      });
    } catch (err) {
      console.error('Failed to fetch video:', err);
      setError('Failed to load video. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [videoId, setCurrentVideo]);

  useEffect(() => {
    if (videoId) {
      fetchVideo();
    }

    // Clear the video context when leaving this page
    return () => {
      setCurrentVideo(null);
    };
  }, [videoId, fetchVideo, setCurrentVideo]);

  /**
   * Handle processing completion - refresh video data
   */
  const handleProcessingComplete = () => {
    fetchVideo();
  };

  /**
   * Handle reprocessing a video - queues it for re-transcription
   */
  const handleReprocess = async () => {
    if (!video) return;

    try {
      setReprocessing(true);
      setReprocessError(null);
      await videoApi.reprocess(video.video_id);
      // Refresh video data to show new processing status
      await fetchVideo();
    } catch (err) {
      console.error('Failed to reprocess video:', err);
      setReprocessError('Failed to start reprocessing. Please try again.');
    } finally {
      setReprocessing(false);
    }
  };

  /**
   * Check if video should show reprocess button
   * Shows for: failed, completed with no transcript, or completed with no summary
   */
  const shouldShowReprocessButton = (videoData: VideoDetailResponse): boolean => {
    if (videoData.processing_status === 'failed') return true;
    if (videoData.processing_status === 'completed') {
      // Show if transcript or summary is missing
      if (!videoData.summary || videoData.summary.trim() === '') return true;
    }
    return false;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 dark:bg-[#0f0f0f]">
        <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="h-8 w-48 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="mt-8 aspect-video w-full rounded-lg bg-gray-200 dark:bg-gray-700" />
            <div className="mt-6 h-8 w-3/4 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="mt-4 h-4 w-1/2 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !video) {
    return (
      <div className="min-h-screen bg-gray-100 dark:bg-[#0f0f0f]">
        <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
          <Link
            href="/library"
            className="inline-flex items-center text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
          >
            <ArrowLeftIcon className="mr-2 h-4 w-4" />
            Back to Library
          </Link>
          <div className="mt-8 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-6 text-center">
            <h2 className="text-lg font-medium text-red-800 dark:text-red-400">
              {error || 'Video not found'}
            </h2>
            <Link
              href="/library"
              className="mt-4 inline-flex items-center rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 transition-colors"
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
    video.thumbnail_url || `https://img.youtube.com/vi/${video.youtube_video_id}/maxresdefault.jpg`;

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-[#0f0f0f]">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Back link */}
        <Link
          href="/library"
          className="inline-flex items-center text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
        >
          <ArrowLeftIcon className="mr-2 h-4 w-4" />
          Back to Library
        </Link>

        {/* Video header */}
        <div className="mt-6 overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/50 shadow-sm">
          {/* Thumbnail with play button */}
          <div className="relative aspect-video w-full bg-gray-100 dark:bg-gray-900">
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
            {/* Status badge - only show if not completed (per design system) */}
            {video.processing_status !== 'completed' && (
              <span
                className={`absolute top-4 right-4 rounded-full px-3 py-1 text-sm font-medium ${statusBadge.className}`}
              >
                {statusBadge.label}
              </span>
            )}
          </div>

          {/* Video info */}
          <div className="p-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{video.title}</h1>

            {/* Channel and metadata */}
            <div className="mt-4 flex flex-wrap items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
              <Link
                href={`/library?channelId=${video.channel.channel_id}`}
                className="font-medium text-red-600 dark:text-red-400 hover:text-red-500 dark:hover:text-red-300"
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
                    className="inline-flex items-center gap-1 rounded-full bg-gray-100 dark:bg-gray-700 px-3 py-1 text-sm text-gray-700 dark:text-gray-300"
                  >
                    <TagIcon className="h-3.5 w-3.5" />
                    {facet.name}
                  </span>
                ))}
              </div>
            )}

            {/* Reprocess Button - shown for failed videos or videos with missing content */}
            {shouldShowReprocessButton(video) && !isProcessing(video.processing_status) && (
              <div className="mt-6 p-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20">
                <div className="flex items-start gap-3">
                  <ArrowPathIcon className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-sm text-amber-800 dark:text-amber-200 font-medium">
                      {video.processing_status === 'failed'
                        ? 'Processing failed for this video'
                        : 'Missing content detected'}
                    </p>
                    <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                      {video.processing_status === 'failed'
                        ? 'The video may have been rate-limited by YouTube or encountered another error. You can try reprocessing it.'
                        : 'This video is missing a transcript or summary. Reprocessing will attempt to fetch and generate the missing content.'}
                    </p>
                    {reprocessError && (
                      <p className="text-sm text-red-600 dark:text-red-400 mt-2">
                        {reprocessError}
                      </p>
                    )}
                    <button
                      onClick={handleReprocess}
                      disabled={reprocessing}
                      className="mt-3 inline-flex items-center gap-2 px-4 py-2 rounded-md bg-amber-600 text-white font-medium text-sm hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <ArrowPathIcon className={`h-4 w-4 ${reprocessing ? 'animate-spin' : ''}`} />
                      {reprocessing ? 'Starting reprocess...' : 'Reprocess Video'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Processing Progress (if still processing) */}
        {isProcessing(video.processing_status) && (
          <div className="mt-6 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/50 p-6">
            <JobProgress videoId={videoId} onComplete={handleProcessingComplete} />
          </div>
        )}

        {/* Tab Navigation (only show when completed) */}
        {video.processing_status === 'completed' && (
          <div className="mt-6 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/50 overflow-hidden">
            {/* Tab Headers */}
            <div className="flex border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/80">
              {(
                [
                  { id: 'summary' as TabId, label: 'Summary', icon: SparklesIcon },
                  { id: 'description' as TabId, label: 'Description', icon: DocumentTextIcon },
                  { id: 'transcript' as TabId, label: 'Transcript', icon: DocumentTextIcon },
                  { id: 'history' as TabId, label: 'History', icon: ChartBarIcon },
                ] as Tab[]
              ).map((tab) => (
                <TabButton
                  key={tab.id}
                  tab={tab}
                  isActive={activeTab === tab.id}
                  onClick={() => setActiveTab(tab.id)}
                />
              ))}
            </div>

            {/* Tab Content */}
            <div className="p-6">
              {/* Summary Tab */}
              {activeTab === 'summary' && (
                <div>
                  {video.summary ? (
                    <MarkdownRenderer content={video.summary} variant="summary" />
                  ) : (
                    <p className="text-gray-500 dark:text-gray-400 italic">
                      No AI summary available for this video.
                    </p>
                  )}
                </div>
              )}

              {/* Description Tab */}
              {activeTab === 'description' && (
                <div className="max-h-[60vh] overflow-y-auto scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600">
                  {video.description ? (
                    <DescriptionRenderer content={video.description} />
                  ) : (
                    <p className="text-gray-500 dark:text-gray-400 italic">
                      No description available for this video.
                    </p>
                  )}
                </div>
              )}

              {/* Transcript Tab */}
              {activeTab === 'transcript' && (
                <TranscriptViewer
                  transcriptUrl={`/api/v1/videos/${video.video_id}/transcript`}
                  videoTitle={video.title}
                />
              )}

              {/* History Tab */}
              {activeTab === 'history' && <ProcessingHistory videoId={video.video_id} />}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
