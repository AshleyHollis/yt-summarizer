'use client';

import { useState, FormEvent } from 'react';
import {
  channelApi,
  ChannelVideosResponse,
  ChannelVideo,
  ApiClientError,
} from '@/services/api';

/**
 * Props for ChannelForm component
 */
export interface ChannelFormProps {
  /** Callback when channel videos are loaded (includes the URL used) */
  onChannelLoaded?: (response: ChannelVideosResponse, channelUrl: string) => void;
  /** Custom class name */
  className?: string;
}

/**
 * YouTube channel URL validation regex
 */
const CHANNEL_URL_REGEX =
  /^(https?:\/\/)?(www\.)?youtube\.com\/(@[\w.-]+|channel\/UC[\w-]+|c\/[\w.-]+|user\/[\w.-]+)/;

/**
 * Form component for entering a YouTube channel URL
 */
export function ChannelForm({ onChannelLoaded, className = '' }: ChannelFormProps) {
  const [channelUrl, setChannelUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Validate channel URL
   */
  const validateUrl = (value: string): string | null => {
    if (!value.trim()) {
      return 'YouTube channel URL is required';
    }

    if (!CHANNEL_URL_REGEX.test(value.trim())) {
      return 'Please enter a valid YouTube channel URL (e.g., https://youtube.com/@ChannelName)';
    }

    return null;
  };

  /**
   * Handle form submission
   */
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    setError(null);

    const validationError = validateUrl(channelUrl);
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsLoading(true);

    try {
      const response = await channelApi.fetchVideos({
        channel_url: channelUrl.trim(),
        limit: 100,
      });
      onChannelLoaded?.(response, channelUrl.trim());
    } catch (err) {
      console.error('Channel fetch error:', err);
      if (err instanceof ApiClientError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred while fetching channel videos');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className={`space-y-4 ${className}`}>
      <div>
        <label
          htmlFor="channel-url"
          className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
        >
          YouTube Channel URL
        </label>
        <div className="flex gap-2">
          <input
            type="url"
            id="channel-url"
            value={channelUrl}
            onChange={(e) => setChannelUrl(e.target.value)}
            placeholder="https://youtube.com/@ChannelName"
            className={`flex-1 px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-800 dark:border-gray-600 dark:text-white ${
              error ? 'border-red-500' : 'border-gray-300'
            }`}
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? (
              <span className="flex items-center gap-2">
                <svg
                  className="animate-spin h-4 w-4"
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
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Loading...
              </span>
            ) : (
              'Fetch Videos'
            )}
          </button>
        </div>
        {error && <p className="mt-1 text-sm text-red-600 dark:text-red-400">{error}</p>}
      </div>
    </form>
  );
}
