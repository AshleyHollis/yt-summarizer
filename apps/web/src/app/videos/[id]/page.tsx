'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { videoApi, VideoResponse, ProcessingStatus } from '@/services/api';
import JobProgress from '@/components/JobProgress';
import TranscriptViewer from '@/components/TranscriptViewer';
import SummaryCard from '@/components/SummaryCard';

/**
 * Video Detail Page
 *
 * Displays video information, processing progress, transcript, and summary.
 */
export default function VideoDetailPage() {
  const params = useParams();
  const videoId = params.id as string;

  const [video, setVideo] = useState<VideoResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  /**
   * Fetch video details
   */
  const fetchVideo = useCallback(async () => {
    try {
      const data = await videoApi.getById(videoId);
      setVideo(data);
      setError(null);
    } catch (err) {
      setError('Failed to load video. Please try again.');
      console.error('Video fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [videoId]);

  /**
   * Initial fetch
   */
  useEffect(() => {
    fetchVideo();
  }, [fetchVideo]);

  /**
   * Handle processing completion - refresh video data
   */
  const handleComplete = () => {
    fetchVideo();
  };

  /**
   * Check if video is still processing
   */
  const isProcessing = (status: ProcessingStatus): boolean => {
    return ['pending', 'transcribing', 'summarizing', 'embedding', 'building_relationships'].includes(
      status
    );
  };

  // Loading state
  if (isLoading) {
    return (
      <main className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
        <div className="max-w-4xl mx-auto animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-8" />
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6">
            <div className="aspect-video bg-gray-200 dark:bg-gray-700 rounded-lg mb-6" />
            <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-4" />
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2" />
          </div>
        </div>
      </main>
    );
  }

  // Error state
  if (error || !video) {
    return (
      <main className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
        <div className="max-w-4xl mx-auto">
          <Link
            href="/submit"
            className="inline-flex items-center gap-2 text-blue-600 dark:text-blue-400 hover:underline mb-6"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Submit
          </Link>

          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-xl p-6 text-center">
            <svg
              className="w-12 h-12 mx-auto mb-4 text-red-500"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <h2 className="text-lg font-semibold text-red-800 dark:text-red-200 mb-2">
              {error || 'Video not found'}
            </h2>
            <p className="text-red-600 dark:text-red-400">
              The video you&apos;re looking for doesn&apos;t exist or couldn&apos;t be loaded.
            </p>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-4">
          <Link
            href="/submit"
            className="inline-flex items-center gap-2 text-blue-600 dark:text-blue-400 hover:underline"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Submit
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Video Info Section */}
        <section className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden mb-8">
          <div className="md:flex">
            {/* Thumbnail */}
            <div className="md:w-1/3">
              {video.thumbnail_url ? (
                <img
                  src={video.thumbnail_url}
                  alt={video.title}
                  className="w-full aspect-video object-cover"
                />
              ) : (
                <div className="w-full aspect-video bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                  <svg
                    className="w-16 h-16 text-gray-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                    />
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                </div>
              )}
            </div>

            {/* Video Details */}
            <div className="p-6 md:w-2/3">
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                {video.title}
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                {video.channel.name}
              </p>

              {video.description && (
                <p className="text-gray-700 dark:text-gray-300 text-sm line-clamp-3 mb-4">
                  {video.description}
                </p>
              )}

              <div className="flex flex-wrap items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
                {video.duration_seconds && (
                  <span className="flex items-center gap-1">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    {formatDuration(video.duration_seconds)}
                  </span>
                )}
                {video.published_at && (
                  <span className="flex items-center gap-1">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                      />
                    </svg>
                    {new Date(video.published_at).toLocaleDateString()}
                  </span>
                )}
                <a
                  href={`https://www.youtube.com/watch?v=${video.youtube_video_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                    />
                  </svg>
                  Watch on YouTube
                </a>
              </div>

              {/* Status Badge */}
              <div className="mt-4">
                <StatusBadge status={video.processing_status} />
              </div>
            </div>
          </div>
        </section>

        {/* Processing Progress (if still processing) */}
        {isProcessing(video.processing_status) && (
          <section className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-8">
            <JobProgress videoId={videoId} onComplete={handleComplete} />
          </section>
        )}

        {/* Summary and Transcript (if completed) */}
        {video.processing_status === 'completed' && (
          <div className="grid lg:grid-cols-2 gap-8">
            {/* Summary */}
            <section>
              <SummaryCard summaryUrl={video.summary_url} videoTitle={video.title} />
            </section>

            {/* Transcript */}
            <section>
              <TranscriptViewer transcriptUrl={video.transcript_url} videoTitle={video.title} />
            </section>
          </div>
        )}

        {/* Related Videos (if available) */}
        {video.related_videos_count > 0 && (
          <section className="mt-8">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Related Videos ({video.related_videos_count})
            </h2>
            <p className="text-gray-500 dark:text-gray-400">
              Related videos feature coming soon...
            </p>
          </section>
        )}
      </div>
    </main>
  );
}

/**
 * Status badge component
 */
function StatusBadge({ status }: { status: ProcessingStatus }) {
  const config: Record<
    ProcessingStatus,
    { label: string; bg: string; text: string; icon?: React.ReactNode }
  > = {
    pending: {
      label: 'Pending',
      bg: 'bg-gray-100 dark:bg-gray-700',
      text: 'text-gray-700 dark:text-gray-300',
    },
    transcribing: {
      label: 'Transcribing',
      bg: 'bg-blue-100 dark:bg-blue-900/50',
      text: 'text-blue-700 dark:text-blue-300',
      icon: <SpinnerIcon />,
    },
    summarizing: {
      label: 'Summarizing',
      bg: 'bg-purple-100 dark:bg-purple-900/50',
      text: 'text-purple-700 dark:text-purple-300',
      icon: <SpinnerIcon />,
    },
    embedding: {
      label: 'Creating Embeddings',
      bg: 'bg-indigo-100 dark:bg-indigo-900/50',
      text: 'text-indigo-700 dark:text-indigo-300',
      icon: <SpinnerIcon />,
    },
    building_relationships: {
      label: 'Finding Related',
      bg: 'bg-cyan-100 dark:bg-cyan-900/50',
      text: 'text-cyan-700 dark:text-cyan-300',
      icon: <SpinnerIcon />,
    },
    completed: {
      label: 'Completed',
      bg: 'bg-green-100 dark:bg-green-900/50',
      text: 'text-green-700 dark:text-green-300',
      icon: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      ),
    },
    failed: {
      label: 'Failed',
      bg: 'bg-red-100 dark:bg-red-900/50',
      text: 'text-red-700 dark:text-red-300',
      icon: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      ),
    },
  };

  const { label, bg, text, icon } = config[status];

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium ${bg} ${text}`}>
      {icon}
      {label}
    </span>
  );
}

/**
 * Spinner icon for in-progress states
 */
function SpinnerIcon() {
  return (
    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
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
