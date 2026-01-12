'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { SmartUrlInput } from '@/components/SmartUrlInput';
import { ChannelVideoList } from '@/components/ChannelVideoList';
import { formatDateShort } from '@/utils/formatDate';
import {
  ChannelVideosResponse,
  batchApi,
  CreateBatchRequest,
  ApiClientError,
} from '@/services/api';

/**
 * Unified Add Content Page
 *
 * Smart URL detection allows users to paste any YouTube URL:
 * - Video URLs → Immediate processing with redirect to video detail
 * - Channel URLs → Browse and select videos for batch ingestion
 */
export default function AddPage() {
  const router = useRouter();
  const [channelData, setChannelData] = useState<ChannelVideosResponse | null>(null);
  const [channelUrl, setChannelUrl] = useState('');
  const [selectedVideoIds, setSelectedVideoIds] = useState<string[]>([]);
  const [batchName, setBatchName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Handle channel data loaded from SmartUrlInput
   */
  const handleChannelLoaded = (response: ChannelVideosResponse, url: string) => {
    setChannelData(response);
    setChannelUrl(url);
    setSelectedVideoIds([]);
    // Auto-generate batch name
    setBatchName(`${response.channel_name} - ${formatDateShort()}`);
  };

  /**
   * Handle video selection changes
   */
  const handleSelectionChange = (ids: string[]) => {
    setSelectedVideoIds(ids);
  };

  /**
   * Start batch ingestion with selected videos
   */
  const handleStartIngestion = async () => {
    if (!channelData || selectedVideoIds.length === 0) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const request: CreateBatchRequest = {
        channel_id: channelData.channel_id || undefined,
        youtube_channel_id: channelData.youtube_channel_id,
        name: batchName || `Channel Import - ${channelData.channel_name}`,
        video_ids: selectedVideoIds,
        ingest_all: false,
      };

      const batch = await batchApi.create(request);
      router.push(`/ingest/${batch.id}`);
    } catch (err) {
      console.error('Batch creation error:', err);
      if (err instanceof ApiClientError) {
        setError(err.message);
      } else {
        setError('Failed to create batch. Please try again.');
      }
      setIsSubmitting(false);
    }
  };

  /**
   * Ingest all videos from the channel
   */
  const handleIngestAll = async () => {
    if (!channelData) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const request: CreateBatchRequest = {
        channel_id: channelData.channel_id || undefined,
        youtube_channel_id: channelData.youtube_channel_id,
        name: batchName || `Full Channel Import - ${channelData.channel_name}`,
        video_ids: [],
        ingest_all: true,
      };

      const batch = await batchApi.create(request);
      router.push(`/ingest/${batch.id}`);
    } catch (err) {
      console.error('Batch creation error:', err);
      if (err instanceof ApiClientError) {
        setError(err.message);
      } else {
        setError('Failed to create batch. Please try again.');
      }
      setIsSubmitting(false);
    }
  };

  /**
   * Reset to initial state
   */
  const handleReset = () => {
    setChannelData(null);
    setChannelUrl('');
    setSelectedVideoIds([]);
    setBatchName('');
    setError(null);
  };

  return (
    <main className="min-h-[calc(100vh-4rem)] bg-gray-100 dark:bg-[#0f0f0f]">
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Header */}
        <section className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Add Content
          </h1>
          <p className="text-gray-700 dark:text-gray-300 max-w-xl mx-auto">
            Paste any YouTube URL — we&apos;ll detect whether it&apos;s a video or channel
          </p>
        </section>

        {/* Smart URL Input */}
        {!channelData && (
          <section className="bg-white dark:bg-gray-800/50 rounded-xl shadow-md border border-gray-300 dark:border-gray-700/50 p-6 md:p-8">
            <SmartUrlInput
              onChannelLoaded={handleChannelLoaded}
              className="max-w-2xl mx-auto"
            />
          </section>
        )}

        {/* Channel Video Selection (shown after channel is loaded) */}
        {channelData && (
          <>
            {/* Back button and channel info */}
            <section className="mb-6">
              <button
                onClick={handleReset}
                className="inline-flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M19 12H5M12 19l-7-7 7-7" />
                </svg>
                Start over with new URL
              </button>
            </section>

            <section className="bg-white dark:bg-gray-800/50 rounded-xl shadow-md border border-gray-300 dark:border-gray-700/50 p-5 md:p-6">
              <div className="space-y-6">
                {/* Channel header */}
                <div className="flex items-center gap-3 pb-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-center w-10 h-10 rounded-full bg-purple-100 dark:bg-purple-900/50">
                    <svg className="w-5 h-5 text-purple-600 dark:text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                    </svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {channelData.channel_name}
                    </h2>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {channelData.videos.length} videos loaded
                    </p>
                  </div>
                </div>

                {/* Batch name input */}
                <div>
                  <label
                    htmlFor="batch-name"
                    className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                  >
                    Batch Name (optional)
                  </label>
                  <input
                    type="text"
                    id="batch-name"
                    value={batchName}
                    onChange={(e) => setBatchName(e.target.value)}
                    placeholder="My Batch Import"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 hover:border-red-400 dark:bg-[#1a1a1a] dark:border-gray-600 dark:text-white"
                  />
                </div>

                {/* Video list */}
                <ChannelVideoList
                  channelData={channelData}
                  channelUrl={channelUrl}
                  onSelectionChange={handleSelectionChange}
                />

                {/* Error message */}
                {error && (
                  <div className="p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-red-700 dark:text-red-400">{error}</p>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-col sm:flex-row gap-4">
                  <button
                    onClick={handleStartIngestion}
                    disabled={selectedVideoIds.length === 0 || isSubmitting}
                    className="flex-1 py-3 px-6 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
                  >
                    {isSubmitting ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg
                          className="animate-spin h-5 w-5"
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                        >
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                          />
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                          />
                        </svg>
                        Creating Batch...
                      </span>
                    ) : (
                      `Ingest Selected (${selectedVideoIds.length})`
                    )}
                  </button>

                  <button
                    onClick={handleIngestAll}
                    disabled={isSubmitting}
                    className="flex-1 py-3 px-6 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
                  >
                    Ingest All Channel Videos
                  </button>
                </div>
              </div>
            </section>
          </>
        )}

        {/* Feature Cards (shown when no channel is loaded) */}
        {!channelData && (
          <section className="mt-10 grid md:grid-cols-2 gap-6">
            <FeatureCard
              icon={<VideoIcon />}
              title="Single Video"
              description="Paste a video URL to instantly process and get AI-powered summaries, transcripts, and key insights."
              color="blue"
            />
            <FeatureCard
              icon={<ChannelIcon />}
              title="Channel Import"
              description="Paste a channel URL to browse all videos and select which ones to batch process."
              color="purple"
            />
          </section>
        )}
      </div>
    </main>
  );
}

/**
 * Feature card component
 */
interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  color: 'blue' | 'purple';
}

function FeatureCard({ icon, title, description, color }: FeatureCardProps) {
  const colorClasses = {
    blue: 'bg-blue-50 dark:bg-blue-900/30 text-blue-500 dark:text-blue-400',
    purple: 'bg-purple-50 dark:bg-purple-900/30 text-purple-500 dark:text-purple-400',
  };

  return (
    <div className="p-6 rounded-xl bg-white dark:bg-gray-800/30 border border-gray-200 dark:border-gray-700/30 shadow-sm">
      <div className={`inline-flex items-center justify-center w-12 h-12 rounded-lg ${colorClasses[color]} mb-4`}>
        {icon}
      </div>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
        {title}
      </h3>
      <p className="text-sm text-gray-600 dark:text-gray-300">{description}</p>
    </div>
  );
}

/**
 * Video icon
 */
function VideoIcon() {
  return (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polygon points="23 7 16 12 23 17 23 7" />
      <rect x="1" y="5" width="15" height="14" rx="2" ry="2" />
    </svg>
  );
}

/**
 * Channel icon
 */
function ChannelIcon() {
  return (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}
