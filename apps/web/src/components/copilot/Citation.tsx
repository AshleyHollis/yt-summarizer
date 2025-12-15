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
      className="block rounded-lg border border-gray-200 p-3 hover:border-blue-300 hover:bg-blue-50 transition-colors"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-sm">
            <span className="font-medium text-gray-900 truncate">
              {videoTitle}
            </span>
            <span className="text-gray-400">@{formatTime(startTime)}</span>
          </div>
          <p className="mt-1 text-sm text-gray-600 line-clamp-2">
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
  const getColorClass = (): string => {
    if (confidence >= 0.8) return "bg-green-100 text-green-800";
    if (confidence >= 0.5) return "bg-yellow-100 text-yellow-800";
    return "bg-gray-100 text-gray-800";
  };

  const percentage = Math.round(confidence * 100);

  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getColorClass()}`}
    >
      {percentage}%
    </span>
  );
}
