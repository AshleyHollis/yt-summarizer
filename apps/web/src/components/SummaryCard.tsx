'use client';

import { useState, useEffect } from 'react';
import { MarkdownRenderer, CollapsibleContent } from '@/components/common';

/**
 * Props for SummaryCard
 */
export interface SummaryCardProps {
  /** URL to fetch summary from */
  summaryUrl: string | null;
  /** Custom class name */
  className?: string;
}

/**
 * Component for displaying AI-generated video summaries
 */
export function SummaryCard({
  summaryUrl,
  className = '',
}: SummaryCardProps) {
  const [summary, setSummary] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isCopied, setIsCopied] = useState(false);

  /**
   * Fetch summary from URL
   */
  useEffect(() => {
    if (!summaryUrl) return;

    const fetchSummary = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await fetch(summaryUrl);
        if (!response.ok) {
          throw new Error('Failed to fetch summary');
        }
        const text = await response.text();
        setSummary(text);
      } catch (err) {
        setError('Failed to load summary. Please try again.');
        console.error('Summary fetch error:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchSummary();
  }, [summaryUrl]);

  /**
   * Copy summary to clipboard
   */
  const handleCopy = async () => {
    if (!summary) return;

    try {
      await navigator.clipboard.writeText(summary);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Not available state
  if (!summaryUrl) {
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
              d="M13 10V3L4 14h7v7l9-11h-7z"
            />
          </svg>
          <p>Summary not available yet</p>
          <p className="text-sm mt-1">Processing may still be in progress</p>
        </div>
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div className={`animate-pulse ${className}`}>
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded mb-4 w-1/3" />
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-4 bg-gray-200 dark:bg-gray-700 rounded" style={{ width: `${90 - i * 10}%` }} />
          ))}
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className={`rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/30 p-6 ${className}`}>
        <p className="text-red-600 dark:text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className={`rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 overflow-hidden ${className}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            AI Summary
          </h3>

          {/* Copy button */}
          <button
            onClick={handleCopy}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            title="Copy summary"
          >
            {isCopied ? (
              <>
                <svg className="w-4 h-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Copied!
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                  />
                </svg>
                Copy
              </>
            )}
          </button>
        </div>
      </div>

      {/* Summary content with Markdown rendering */}
      <div className="p-4">
        <CollapsibleContent
          collapsedHeight={300}
          defaultExpanded={true}
          expandLabel="Show full summary"
          collapseLabel="Collapse"
        >
          <MarkdownRenderer content={summary || ''} variant="summary" />
        </CollapsibleContent>
      </div>
    </div>
  );
}

export default SummaryCard;
