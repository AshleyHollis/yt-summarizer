"use client";

import { Clock, ExternalLink } from "lucide-react";

/**
 * Known garbage text prefixes that occasionally appear in AI-generated descriptions
 * due to model hallucinations or parsing errors. These should be filtered out.
 */
const GARBAGE_TEXT_PREFIXES = ["orm"] as const;

interface KeyMoment {
  timestamp: string;
  description: string;
  segmentId?: string | null;
  youTubeUrl?: string | null;
}

interface KeyMomentsListProps {
  moments: KeyMoment[];
  className?: string;
}

/**
 * Displays key moments from a video that support the recommendation.
 * Each moment includes a clickable timestamp link to YouTube.
 * US5 - Transparency feature.
 */
export function KeyMomentsList({ moments, className = "" }: KeyMomentsListProps) {
  // Filter out moments with empty/invalid timestamps or descriptions
  const validMoments = moments.filter(m => 
    m.timestamp && 
    m.timestamp !== "0:00" &&
    m.description && 
    m.description.length > 5 &&
    !GARBAGE_TEXT_PREFIXES.some(prefix => m.description.startsWith(prefix))
  );

  if (validMoments.length === 0) {
    return null;
  }

  return (
    <div className={`${className}`}>
      <div className="flex items-center gap-1.5 mb-1.5">
        <Clock className="w-3 h-3 text-gray-400 dark:text-gray-500" />
        <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Jump to</span>
      </div>
      <ul className="space-y-1">
        {validMoments.slice(0, 3).map((moment, index) => (
          <li key={index} className="text-sm">
            {moment.youTubeUrl ? (
              <a
                href={moment.youTubeUrl}
                target="_blank"
                rel="noopener noreferrer"
                data-testid="key-moment-link"
                className="inline-flex items-center gap-1.5 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:underline"
              >
                <span className="font-mono text-xs bg-red-100 dark:bg-red-900/50 px-1.5 py-0.5 rounded">
                  {moment.timestamp}
                </span>
                <span className="text-gray-700 dark:text-gray-300 text-xs truncate max-w-[200px]">
                  {moment.description}
                </span>
                <ExternalLink className="w-3 h-3 flex-shrink-0" />
              </a>
            ) : (
              <span className="inline-flex items-center gap-1.5">
                <span className="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded text-gray-500 dark:text-gray-400">
                  {moment.timestamp}
                </span>
                <span className="text-gray-600 dark:text-gray-400 text-xs truncate max-w-[200px]">
                  {moment.description}
                </span>
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
