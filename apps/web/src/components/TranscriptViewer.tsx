'use client';

import { useState, useEffect } from 'react';
import { getClientApiUrl } from '@/services/runtimeConfig';

/**
 * Props for TranscriptViewer
 */
export interface TranscriptViewerProps {
  /** URL to fetch transcript from */
  transcriptUrl: string | null;
  /** Video title for display */
  videoTitle?: string;
  /** Custom class name */
  className?: string;
}

/**
 * Component for displaying video transcripts with search and scroll
 */
export function TranscriptViewer({
  transcriptUrl,
  videoTitle,
  className = '',
}: TranscriptViewerProps) {
  const [transcript, setTranscript] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);

  /**
   * Fetch transcript from URL
   */
  useEffect(() => {
    if (!transcriptUrl) return;

    const fetchTranscript = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const baseUrl = getClientApiUrl();
        const fullUrl = transcriptUrl.startsWith('http') ? transcriptUrl : `${baseUrl}${transcriptUrl}`;
        const response = await fetch(fullUrl);
        if (!response.ok) {
          throw new Error('Failed to fetch transcript');
        }
        const text = await response.text();
        setTranscript(text);
      } catch (err) {
        setError('Failed to load transcript. Please try again.');
        console.error('Transcript fetch error:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchTranscript();
  }, [transcriptUrl]);

  /**
   * Highlight search terms in transcript
   */
  const highlightedTranscript = () => {
    if (!transcript || !searchQuery.trim()) {
      return transcript;
    }

    const regex = new RegExp(`(${searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return transcript.replace(
      regex,
      '<mark class="bg-yellow-200 dark:bg-yellow-800 rounded px-0.5">$1</mark>'
    );
  };

  /**
   * Count search matches
   */
  const matchCount = () => {
    if (!transcript || !searchQuery.trim()) return 0;
    const regex = new RegExp(searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    return (transcript.match(regex) || []).length;
  };

  // Not available state
  if (!transcriptUrl) {
    return (
      <div className={`rounded-lg border border-gray-200 dark:border-gray-700 p-6 ${className}`}>
        <div className="text-center text-gray-500 dark:text-gray-400">
          <svg
            className="w-12 h-12 mx-auto mb-3 opacity-50"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <p>Transcript not available yet</p>
          <p className="text-sm mt-1">Processing may still be in progress</p>
        </div>
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div className={`animate-pulse ${className}`}>
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded mb-4" />
        <div className="space-y-2">
          {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
            <div key={i} className="h-4 bg-gray-200 dark:bg-gray-700 rounded" />
          ))}
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div
        className={`rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/30 p-6 ${className}`}
      >
        <p className="text-red-600 dark:text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div
      className={`rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 ${className}`}
    >
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Transcript</h3>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-sm text-red-600 dark:text-red-400 hover:underline"
          >
            {isExpanded ? 'Collapse' : 'Expand'}
          </button>
        </div>

        {/* Search input */}
        <div className="relative">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search transcript..."
            className="w-full px-4 py-2 pl-10 rounded-lg border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500 hover:border-red-400 transition-colors"
          />
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          {searchQuery && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500 dark:text-gray-400">
              {matchCount()} {matchCount() === 1 ? 'match' : 'matches'}
            </span>
          )}
        </div>
      </div>

      {/* Transcript content */}
      <div
        className={`p-4 overflow-y-auto text-gray-700 dark:text-gray-300 leading-relaxed ${
          isExpanded ? 'max-h-[600px]' : 'max-h-[300px]'
        }`}
      >
        {videoTitle && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            Transcript for: <span className="font-medium">{videoTitle}</span>
          </p>
        )}
        <div
          className="whitespace-pre-wrap"
          dangerouslySetInnerHTML={{ __html: highlightedTranscript() || '' }}
        />
      </div>

      {/* Footer with word count */}
      <div className="p-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50">
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {transcript?.split(/\s+/).length.toLocaleString()} words
        </p>
      </div>
    </div>
  );
}

export default TranscriptViewer;
