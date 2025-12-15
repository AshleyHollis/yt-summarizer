"use client";

import { Citation } from "./Citation";
import { CopilotVideoCard } from "./CopilotVideoCard";
import { FollowupButtons } from "./FollowupButtons";
import { UncertaintyMessage } from "./UncertaintyMessage";

interface Evidence {
  videoId: string;
  youTubeVideoId: string;
  videoTitle: string;
  segmentId: string;
  segmentText: string;
  startTime: number;
  endTime: number;
  youTubeUrl: string;
  confidence: number;
}

interface RecommendedVideo {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string | null;
  duration?: number | null;
  relevanceScore: number;
  primaryReason: string;
}

interface CopilotMessageProps {
  answer: string;
  evidence?: Evidence[];
  videoCards?: RecommendedVideo[];
  followups?: string[];
  uncertainty?: string | null;
  onFollowupClick?: (suggestion: string) => void;
}

export function CopilotMessage({
  answer,
  evidence = [],
  videoCards = [],
  followups = [],
  uncertainty,
  onFollowupClick,
}: CopilotMessageProps) {
  return (
    <div className="space-y-4">
      {/* Uncertainty warning if present */}
      {uncertainty && <UncertaintyMessage message={uncertainty} />}

      {/* Main answer */}
      <div className="prose prose-sm max-w-none">
        <p className="text-gray-700 whitespace-pre-wrap">{answer}</p>
      </div>

      {/* Video cards */}
      {videoCards.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            Recommended Videos
          </h4>
          <div className="space-y-2">
            {videoCards.slice(0, 3).map((video) => (
              <CopilotVideoCard
                key={video.videoId}
                {...video}
              />
            ))}
          </div>
        </div>
      )}

      {/* Evidence citations */}
      {evidence.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            Sources
          </h4>
          <div className="space-y-2">
            {evidence.slice(0, 5).map((ev) => (
              <Citation key={ev.segmentId} {...ev} />
            ))}
          </div>
        </div>
      )}

      {/* Follow-up suggestions */}
      {onFollowupClick && followups.length > 0 && (
        <FollowupButtons
          suggestions={followups}
          onFollowupClick={onFollowupClick}
        />
      )}
    </div>
  );
}
