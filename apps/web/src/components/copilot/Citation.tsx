"use client";

interface CitationProps {
  videoId: string;
  videoTitle: string;
  segmentText: string;
  startTime: number;
  endTime: number;
  youTubeUrl: string;
  confidence: number;
}

export function Citation({
  videoTitle,
  segmentText,
  startTime,
  youTubeUrl,
  confidence,
}: CitationProps) {
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  return (
    <a
      href={youTubeUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-3 hover:border-red-400 dark:hover:border-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-sm">
            <span className="font-medium text-gray-900 dark:text-gray-100 truncate">
              {videoTitle}
            </span>
            <span className="text-gray-400 dark:text-gray-500">@{formatTime(startTime)}</span>
          </div>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
            &ldquo;{segmentText}&rdquo;
          </p>
        </div>
        <div className="flex-shrink-0">
          <ConfidenceBadge confidence={confidence} />
        </div>
      </div>
    </a>
  );
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  // Rescale score to match user expectations.
  // Sources shown have already passed our relevance filter, so they ARE relevant.
  // A source directly about the topic (0.5+ raw) should show as 90-100%.
  // Scale range: 0.3 raw → 70%, 0.6+ raw → 100%
  const minScore = 0.3;
  const maxScore = 0.6;
  const minDisplay = 70;
  const maxDisplay = 100;

  const clampedScore = Math.max(minScore, Math.min(confidence, maxScore));
  const rescaledScore = minDisplay + ((clampedScore - minScore) / (maxScore - minScore)) * (maxDisplay - minDisplay);
  const percentage = Math.round(rescaledScore);

  // Color based on display percentage
  const getColorClass = (): string => {
    if (percentage >= 90) return 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
    if (percentage >= 80) return 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300';
    return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300';
  };

  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getColorClass()}`}
      title={`${percentage}% match with your query`}
    >
      {percentage}%
    </span>
  );
}
