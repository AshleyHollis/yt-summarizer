'use client';

import { useState, useEffect, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import {
  videoApi,
  channelApi,
  SubmitVideoResponse,
  ChannelVideosResponse,
  ApiClientError,
} from '@/services/api';

/**
 * URL type detection result
 */
type UrlType = 'unknown' | 'video' | 'channel';

/**
 * YouTube URL patterns
 */
const VIDEO_URL_REGEX =
  /^(https?:\/\/)?(www\.)?(youtube\.com\/(watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/)[\w-]{11}(&.*)?$/;

const CHANNEL_URL_REGEX =
  /^(https?:\/\/)?(www\.)?youtube\.com\/(@[\w.-]+|channel\/UC[\w-]+|c\/[\w.-]+|user\/[\w.-]+)/;

/**
 * Detect the type of YouTube URL
 */
function detectUrlType(url: string): UrlType {
  const trimmed = url.trim();
  if (!trimmed) return 'unknown';
  
  if (VIDEO_URL_REGEX.test(trimmed)) return 'video';
  if (CHANNEL_URL_REGEX.test(trimmed)) return 'channel';
  
  return 'unknown';
}

/**
 * Props for SmartUrlInput
 */
export interface SmartUrlInputProps {
  /** Callback when channel videos are loaded */
  onChannelLoaded?: (response: ChannelVideosResponse, channelUrl: string) => void;
  /** Custom class name */
  className?: string;
}

/**
 * Smart URL input that auto-detects video vs channel URLs
 */
export function SmartUrlInput({ onChannelLoaded, className = '' }: SmartUrlInputProps) {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [urlType, setUrlType] = useState<UrlType>('unknown');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<SubmitVideoResponse | null>(null);

  // Detect URL type as user types
  useEffect(() => {
    const detected = detectUrlType(url);
    setUrlType(detected);
    // Clear error when URL type changes
    if (detected !== 'unknown') {
      setError(null);
    }
  }, [url]);

  /**
   * Handle video submission
   */
  const handleVideoSubmit = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await videoApi.submit({ url: url.trim() });
      setSuccess(response);
      
      // Navigate to video page after short delay
      setTimeout(() => {
        router.push(`/videos/${response.video_id}`);
      }, 1500);
    } catch (err) {
      console.error('Video submission error:', err);
      if (err instanceof ApiClientError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred while processing the video');
      }
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle channel fetch
   */
  const handleChannelFetch = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await channelApi.fetchVideos({
        channel_url: url.trim(),
        limit: 100,
      });
      onChannelLoaded?.(response, url.trim());
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

  /**
   * Handle form submission
   */
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!url.trim()) {
      setError('Please enter a YouTube URL');
      return;
    }

    if (urlType === 'video') {
      await handleVideoSubmit();
    } else if (urlType === 'channel') {
      await handleChannelFetch();
    } else {
      setError('Please enter a valid YouTube video or channel URL');
    }
  };

  /**
   * Get button text based on URL type
   */
  const getButtonText = () => {
    if (isLoading) {
      return urlType === 'video' ? 'Processing...' : 'Loading...';
    }
    switch (urlType) {
      case 'video':
        return 'Process Video';
      case 'channel':
        return 'View Channel Videos';
      default:
        return 'Enter URL';
    }
  };

  /**
   * Get placeholder text
   */
  const getPlaceholder = () => {
    return 'Paste any YouTube URL (video or channel)...';
  };

  return (
    <div className={`w-full ${className}`}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* URL Input with type detection indicator */}
        <div className="space-y-2">
          <label
            htmlFor="youtube-url"
            className="block text-sm font-medium text-gray-700 dark:text-gray-300"
          >
            YouTube URL
          </label>
          <div className="relative">
            <input
              id="youtube-url"
              type="url"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError(null);
                setSuccess(null);
              }}
              placeholder={getPlaceholder()}
              className={`
                w-full px-4 py-3 pr-12 rounded-lg border
                text-gray-900 dark:text-white
                bg-white dark:bg-[#1a1a1a]
                placeholder-gray-400 dark:placeholder-gray-500
                focus:outline-none focus:ring-2 focus:ring-red-500
                hover:border-red-400
                disabled:opacity-50 disabled:cursor-not-allowed
                ${error ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'}
              `}
              disabled={isLoading}
              aria-invalid={!!error}
              aria-describedby={error ? 'url-error' : urlType !== 'unknown' ? 'url-type' : undefined}
            />
            {/* URL type indicator */}
            {urlType !== 'unknown' && !isLoading && (
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                {urlType === 'video' ? (
                  <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300">
                    <VideoIcon className="w-4 h-4" />
                    <span className="text-xs font-medium">Video</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-purple-100 dark:bg-purple-900/50 text-purple-700 dark:text-purple-300">
                    <ChannelIcon className="w-4 h-4" />
                    <span className="text-xs font-medium">Channel</span>
                  </div>
                )}
              </div>
            )}
            {/* Loading spinner */}
            {isLoading && (
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                <svg
                  className="animate-spin h-5 w-5 text-red-500"
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
              </div>
            )}
          </div>
          
          {/* URL type hint */}
          {urlType !== 'unknown' && (
            <p id="url-type" className="text-sm text-gray-500 dark:text-gray-400">
              {urlType === 'video' 
                ? '📹 Video detected — will process and generate AI summary'
                : '📺 Channel detected — will show videos for batch selection'}
            </p>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div
            id="url-error"
            className="p-3 rounded-lg bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800"
            role="alert"
          >
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Success Message (for video submissions) */}
        {success && (
          <div
            className="p-4 rounded-lg bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800"
            role="status"
          >
            <div className="flex items-start gap-3">
              <svg
                className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
              <div>
                <p className="text-sm font-medium text-green-800 dark:text-green-200">
                  Video submitted successfully!
                </p>
                <p className="text-sm text-green-700 dark:text-green-300 mt-1">
                  &quot;{success.title}&quot; is now being processed. Redirecting...
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading || !url.trim() || urlType === 'unknown'}
          className={`
            w-full py-3 px-4 rounded-lg font-medium
            text-white transition-colors duration-200
            focus:outline-none focus:ring-2 focus:ring-offset-2
            disabled:opacity-50 disabled:cursor-not-allowed
            ${urlType === 'channel' 
              ? 'bg-purple-600 hover:bg-purple-700 focus:ring-purple-500' 
              : 'bg-red-600 hover:bg-red-700 focus:ring-red-500'}
          `}
        >
          {getButtonText()}
        </button>

        {/* Helper Text */}
        <p className="text-sm text-gray-600 dark:text-gray-300 text-center">
          Paste a video URL to process instantly, or a channel URL to browse and select videos.
        </p>
      </form>
    </div>
  );
}

/**
 * Video icon component
 */
function VideoIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polygon points="23 7 16 12 23 17 23 7" />
      <rect x="1" y="5" width="15" height="14" rx="2" ry="2" />
    </svg>
  );
}

/**
 * Channel icon component
 */
function ChannelIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

export default SmartUrlInput;
