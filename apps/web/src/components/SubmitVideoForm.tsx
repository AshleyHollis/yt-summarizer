'use client';

import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { videoApi, SubmitVideoResponse, ApiClientError } from '@/services/api';

/**
 * Form validation error
 */
interface FormError {
  field?: string;
  message: string;
}

/**
 * Props for SubmitVideoForm
 */
export interface SubmitVideoFormProps {
  /** Callback when video is successfully submitted */
  onSuccess?: (response: SubmitVideoResponse) => void;
  /** Custom class name */
  className?: string;
}

/**
 * YouTube URL validation regex
 */
const YOUTUBE_URL_REGEX =
  /^(https?:\/\/)?(www\.)?(youtube\.com\/(watch\?v=|embed\/|v\/)|youtu\.be\/)[\w-]{11}(&.*)?$/;

/**
 * Form component for submitting YouTube videos for processing
 */
export function SubmitVideoForm({ onSuccess, className = '' }: SubmitVideoFormProps) {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<FormError | null>(null);
  const [success, setSuccess] = useState<SubmitVideoResponse | null>(null);

  /**
   * Validate YouTube URL
   */
  const validateUrl = (value: string): FormError | null => {
    if (!value.trim()) {
      return { field: 'url', message: 'YouTube URL is required' };
    }

    if (!YOUTUBE_URL_REGEX.test(value.trim())) {
      return {
        field: 'url',
        message: 'Please enter a valid YouTube URL (e.g., https://youtube.com/watch?v=...)',
      };
    }

    return null;
  };

  /**
   * Handle form submission
   */
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    // Clear previous state
    setError(null);
    setSuccess(null);

    // Validate URL
    const validationError = validateUrl(url);
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await videoApi.submit({ url: url.trim() });
      setSuccess(response);

      // Call success callback
      onSuccess?.(response);

      // Navigate to video page after short delay
      setTimeout(() => {
        router.push(`/videos/${response.video_id}`);
      }, 1500);
    } catch (err) {
      console.error('Video submission error:', err);
      if (err instanceof ApiClientError) {
        setError({
          message: err.message,
          field: err.details?.[0]?.field,
        });
      } else {
        const errorMessage = err instanceof Error ? err.message : String(err);
        console.error('Unexpected error details:', errorMessage);
        setError({
          message: `An unexpected error occurred: ${errorMessage}`,
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={`w-full max-w-2xl mx-auto ${className}`}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* URL Input */}
        <div>
          <label
            htmlFor="youtube-url"
            className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
          >
            YouTube Video URL
          </label>
          <div className="relative">
            <input
              id="youtube-url"
              type="url"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError(null);
              }}
              placeholder="https://www.youtube.com/watch?v=..."
              className={`
                w-full px-4 py-3 rounded-lg border
                text-gray-900 dark:text-white
                bg-white dark:bg-gray-800
                placeholder-gray-400 dark:placeholder-gray-500
                focus:outline-none focus:ring-2 focus:ring-red-500
                disabled:opacity-50 disabled:cursor-not-allowed
                ${error?.field === 'url' ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'}
              `}
              disabled={isSubmitting}
              aria-invalid={error?.field === 'url'}
              aria-describedby={error ? 'url-error' : undefined}
            />
            {/* Loading spinner inside input */}
            {isSubmitting && (
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
        </div>

        {/* Error Message */}
        {error && (
          <div
            id="url-error"
            className="p-3 rounded-lg bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800"
            role="alert"
          >
            <p className="text-sm text-red-600 dark:text-red-400">{error.message}</p>
          </div>
        )}

        {/* Success Message */}
        {success && (
          <div
            className="p-4 rounded-lg bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800"
            role="status"
          >
            <div className="flex items-start gap-3">
              <svg
                className="h-5 w-5 text-green-500 mt-0.5"
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
          disabled={isSubmitting || !url.trim()}
          className={`
            w-full py-3 px-4 rounded-lg font-medium
            text-white bg-red-600 hover:bg-red-700
            focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2
            disabled:opacity-50 disabled:cursor-not-allowed
            transition-colors duration-200
          `}
        >
          {isSubmitting ? 'Submitting...' : 'Process Video'}
        </button>

        {/* Helper Text */}
        <p className="text-sm text-gray-600 dark:text-gray-300 text-center">
          Paste a YouTube URL to extract the transcript and generate an AI summary.
        </p>
      </form>
    </div>
  );
}

export default SubmitVideoForm;
