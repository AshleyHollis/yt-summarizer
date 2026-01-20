'use client';

import { useState } from 'react';
import Link from 'next/link';
import { WhyThisButton } from './WhyThisButton';
import { ExplanationPanel } from './ExplanationPanel';
import { formatDuration } from '@/utils/formatDuration';

interface KeyMoment {
  timestamp: string;
  description: string;
  segmentId?: string | null;
  youTubeUrl?: string | null;
}

interface VideoExplanation {
  summary: string;
  keyMoments: KeyMoment[];
  relatedTo?: string | null;
}

interface CopilotVideoCardProps {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string | null;
  duration?: number | null;
  relevanceScore: number;
  primaryReason: string;
  explanation?: VideoExplanation | null;
}

export function CopilotVideoCard({
  videoId,
  youTubeVideoId,
  title,
  channelName,
  thumbnailUrl,
  duration,
  relevanceScore,
  primaryReason,
  explanation,
}: CopilotVideoCardProps) {
  const [isExplanationExpanded, setIsExplanationExpanded] = useState(false);

  const defaultThumbnail = `https://img.youtube.com/vi/${youTubeVideoId}/mqdefault.jpg`;

  return (
    <div className="w-full group rounded-xl border border-[var(--copilot-kit-separator-color)] p-3 hover:border-[var(--copilot-kit-primary-color)] bg-[var(--copilot-kit-background-color)] transition-all duration-150 cursor-pointer">
      <div className="flex gap-2.5">
        {/* Thumbnail */}
        <Link href={`/videos/${videoId}`} className="flex-shrink-0">
          <div className="relative w-28 h-16 rounded-lg overflow-hidden bg-[var(--copilot-kit-secondary-color)] shadow-sm group-hover:shadow transition-shadow">
            <img
              src={thumbnailUrl || defaultThumbnail}
              alt={title}
              className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-105"
            />
            {duration && (
              <span className="absolute bottom-1 right-1 bg-black/85 text-white text-[10px] font-semibold px-1.5 py-0.5 rounded">
                {formatDuration(duration)}
              </span>
            )}
            {/* Play overlay on hover */}
            <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center">
              <div className="w-7 h-7 rounded-full bg-red-600/95 shadow-lg flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all scale-75 group-hover:scale-100">
                <svg
                  className="w-3.5 h-3.5 text-white ml-0.5"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M8 5v14l11-7z" />
                </svg>
              </div>
            </div>
          </div>
        </Link>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <Link href={`/videos/${videoId}`}>
            <h3 className="text-sm font-semibold text-[var(--copilot-kit-secondary-contrast-color)] line-clamp-2 group-hover:text-[var(--copilot-kit-primary-color)] transition-colors leading-snug">
              {title}
            </h3>
          </Link>
          <p className="text-xs text-[var(--copilot-kit-muted-color)] mt-1.5 flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20">
              <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
            </svg>
            <span className="truncate">{channelName}</span>
          </p>
          <div className="mt-2">
            <p className="text-xs text-[var(--copilot-kit-muted-color)] line-clamp-1 italic">
              "{primaryReason}"
            </p>
            {/* US5: "Why this?" button - only show if explanation available */}
            {explanation && (
              <div className="mt-1.5">
                <WhyThisButton
                  onClick={() => setIsExplanationExpanded(!isExplanationExpanded)}
                  isExpanded={isExplanationExpanded}
                />
              </div>
            )}
          </div>
        </div>

        {/* Relevance indicator */}
        <div className="flex-shrink-0 self-start">
          <RelevanceIndicator score={relevanceScore} />
        </div>
      </div>

      {/* US5: Explanation panel - shown when "Why this?" is clicked */}
      {explanation && isExplanationExpanded && <ExplanationPanel explanation={explanation} />}
    </div>
  );
}

function RelevanceIndicator({ score }: { score: number }) {
  // Rescale score to match user expectations.
  // Videos shown have already passed our relevance filter (0.3+), so they ARE relevant.
  // A video directly about the topic (0.5+ raw) should show as 90-100%.
  // Scale range: 0.3 raw → 70%, 0.6+ raw → 100%
  const minScore = 0.3;
  const maxScore = 0.6;
  const minDisplay = 70;
  const maxDisplay = 100;

  const clampedScore = Math.max(minScore, Math.min(score, maxScore));
  const rescaledScore =
    minDisplay + ((clampedScore - minScore) / (maxScore - minScore)) * (maxDisplay - minDisplay);
  const percentage = Math.round(rescaledScore);

  // Color based on display percentage
  const getColorClass = (): string => {
    if (percentage >= 90) return 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10';
    if (percentage >= 80) return 'text-blue-600 dark:text-blue-400 bg-blue-500/10';
    return 'text-amber-600 dark:text-amber-400 bg-amber-500/10';
  };

  return (
    <div
      className={`flex items-center justify-center px-2 py-1 rounded-lg text-[10px] font-bold ${getColorClass()} border border-current/20`}
      title={`${percentage}% match with your query`}
    >
      <svg className="w-2.5 h-2.5 mr-0.5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" />
      </svg>
      {percentage}%
    </div>
  );
}
