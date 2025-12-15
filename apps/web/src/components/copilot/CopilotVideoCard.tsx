"use client";

import Link from "next/link";

interface CopilotVideoCardProps {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string | null;
  duration?: number | null;
  relevanceScore: number;
  primaryReason: string;
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
}: CopilotVideoCardProps) {
  const formatDuration = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
    }
    return `${minutes}:${secs.toString().padStart(2, "0")}`;
  };

  const defaultThumbnail = `https://img.youtube.com/vi/${youTubeVideoId}/mqdefault.jpg`;

  return (
    <div className="flex gap-3 rounded-lg border border-gray-200 p-3 hover:bg-gray-50 transition-colors">
      {/* Thumbnail */}
      <Link href={`/videos/${videoId}`} className="flex-shrink-0">
        <div className="relative w-24 h-16 rounded overflow-hidden bg-gray-100">
          <img
            src={thumbnailUrl || defaultThumbnail}
            alt={title}
            className="w-full h-full object-cover"
          />
          {duration && (
            <span className="absolute bottom-0.5 right-0.5 bg-black/80 text-white text-xs px-1 rounded">
              {formatDuration(duration)}
            </span>
          )}
        </div>
      </Link>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <Link href={`/videos/${videoId}`}>
          <h3 className="text-sm font-medium text-gray-900 line-clamp-1 hover:text-blue-600">
            {title}
          </h3>
        </Link>
        <p className="text-xs text-gray-500">{channelName}</p>
        <p className="mt-1 text-xs text-blue-600 line-clamp-1">
          {primaryReason}
        </p>
      </div>

      {/* Relevance indicator */}
      <div className="flex-shrink-0">
        <RelevanceIndicator score={relevanceScore} />
      </div>
    </div>
  );
}

function RelevanceIndicator({ score }: { score: number }) {
  // Convert score to bars (3 bars max)
  const bars = Math.ceil(score * 3);

  return (
    <div className="flex items-center gap-0.5" title={`${Math.round(score * 100)}% relevant`}>
      {[1, 2, 3].map((i) => (
        <div
          key={i}
          className={`w-1 rounded-full ${
            i <= bars ? "bg-blue-500" : "bg-gray-200"
          }`}
          style={{ height: `${8 + i * 3}px` }}
        />
      ))}
    </div>
  );
}
