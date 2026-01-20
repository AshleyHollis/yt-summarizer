'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChannelForm } from '@/components/ChannelForm';
import { ChannelVideoList } from '@/components/ChannelVideoList';
import { formatDateShort } from '@/utils/formatDate';
import {
  ChannelVideosResponse,
  batchApi,
  CreateBatchRequest,
  ApiClientError,
} from '@/services/api';

/**
 * Channel ingestion page - select and ingest videos from a YouTube channel
 */
export default function IngestPage() {
  const router = useRouter();
  const [channelData, setChannelData] = useState<ChannelVideosResponse | null>(null);
  const [channelUrl, setChannelUrl] = useState('');
  const [selectedVideoIds, setSelectedVideoIds] = useState<string[]>([]);
  const [batchName, setBatchName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Handle channel data loaded
   */
  const handleChannelLoaded = (response: ChannelVideosResponse, url: string) => {
    setChannelData(response);
    setChannelUrl(url);
    setSelectedVideoIds([]);
    // Auto-generate batch name
    setBatchName(`${response.channel_name} - ${formatDateShort()}`);
  };

  /**
   * Handle selection changes
   */
  const handleSelectionChange = (ids: string[]) => {
    setSelectedVideoIds(ids);
  };

  /**
   * Start batch ingestion
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

      // Navigate to batch progress page
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

      // Navigate to batch progress page
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

  return (
    <main className="min-h-screen bg-gray-100 dark:bg-[#0f0f0f]">
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Ingest from Channel</h1>
          <p className="text-gray-700 dark:text-gray-300 mt-2">
            Enter a YouTube channel URL to browse and select videos for batch ingestion.
          </p>
        </div>

        {/* Channel URL form */}
        <section className="bg-white dark:bg-gray-800/50 rounded-xl shadow-md border border-gray-300 dark:border-gray-700/50 p-5 md:p-6 mb-8">
          <ChannelForm onChannelLoaded={handleChannelLoaded} />
        </section>

        {/* Channel videos */}
        {channelData && (
          <section className="bg-white dark:bg-gray-800/50 rounded-xl shadow-md border border-gray-300 dark:border-gray-700/50 p-5 md:p-6">
            <div className="space-y-6">
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
                  className="flex-1 py-3 px-6 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
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
        )}
      </div>
    </main>
  );
}
