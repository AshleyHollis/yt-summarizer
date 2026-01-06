"use client";

import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  BookOpen,
  ExternalLink,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import { copilotBoxStyles, copilotTextSizes, copilotColors, copilotButtonStyles } from "./copilotStyles";

/**
 * Evidence for a learning path item - links back to source video segments
 */
interface Evidence {
  videoId: string;
  videoTitle: string;
  segmentText: string;
  timestampStart: number;
  timestampEnd: number;
  youTubeUrl: string;
}

/**
 * Individual item in a learning path
 */
interface LearningPathItem {
  order: number;
  videoId: string;
  title: string;
  description: string;
  estimatedDuration: number;
  rationale: string;
  learningObjectives: string[];
  prerequisites: number[];
  evidence: Evidence[];
}

/**
 * Complete learning path structure
 */
interface LearningPath {
  title: string;
  description: string;
  estimatedDuration: number;
  items: LearningPathItem[];
  gaps: string[];
}

interface LearningPathViewProps {
  learningPath: LearningPath;
  onVideoClick?: (videoId: string) => void;
}

/**
 * Format seconds to human-readable duration (e.g., "1h 23m" or "45m")
 */
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) {
    return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  }
  return `${minutes}m`;
}

/**
 * Format timestamp to MM:SS or HH:MM:SS format
 */
function formatTimestamp(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (hours > 0) {
    return `${hours}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  }
  return `${minutes}:${secs.toString().padStart(2, "0")}`;
}

/**
 * Component for displaying a single learning path item
 */
function LearningPathItemCard({
  item,
  isFirst,
  isLast,
  onVideoClick,
}: {
  item: LearningPathItem;
  isFirst: boolean;
  isLast: boolean;
  onVideoClick?: (videoId: string) => void;
}) {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="relative">
      {/* Connector line */}
      {!isLast && (
        <div 
          className="absolute left-4 top-10 w-0.5 h-[calc(100%+8px)] bg-[var(--copilot-kit-separator-color)]" 
          aria-hidden="true"
        />
      )}
      
      <div 
        className={`${copilotBoxStyles.full} cursor-pointer relative z-10`}
        onClick={() => setIsExpanded(!isExpanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setIsExpanded(!isExpanded);
          }
        }}
        aria-expanded={isExpanded}
      >
        {/* Header */}
        <div className="flex items-start gap-3">
          {/* Step number */}
          <div 
            className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--copilot-kit-primary-color)] text-white flex items-center justify-center text-sm font-medium"
            aria-label={`Step ${item.order}`}
          >
            {item.order}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className={`${copilotTextSizes.body} ${copilotColors.primary} font-medium truncate`}>
                {item.title}
              </h4>
              {isExpanded ? (
                <ChevronDown className="w-4 h-4 text-[var(--copilot-kit-muted-color)] flex-shrink-0" />
              ) : (
                <ChevronRight className="w-4 h-4 text-[var(--copilot-kit-muted-color)] flex-shrink-0" />
              )}
            </div>
            
            <div className="flex items-center gap-3">
              <span className={`flex items-center gap-1 ${copilotTextSizes.small} ${copilotColors.muted}`}>
                <Clock className="w-3.5 h-3.5" />
                {formatDuration(item.estimatedDuration)}
              </span>
              {item.prerequisites.length > 0 && (
                <span className={`${copilotTextSizes.small} ${copilotColors.muted}`}>
                  Requires: Step{item.prerequisites.length > 1 ? "s" : ""}{" "}
                  {item.prerequisites.join(", ")}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Expanded content */}
        {isExpanded && (
          <div className="mt-4 ml-11 space-y-4">
            {/* Description */}
            <p className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
              {item.description}
            </p>

            {/* Rationale - Why this video */}
            <div className={`p-3 rounded-lg ${copilotColors.bg.primary} border ${copilotColors.border.default}`}>
              <h5 className={`${copilotTextSizes.small} ${copilotColors.accent} font-medium mb-1 flex items-center gap-1.5`}>
                <BookOpen className="w-3.5 h-3.5" />
                Why this video?
              </h5>
              <p className={`${copilotTextSizes.small} ${copilotColors.primary}`}>
                {item.rationale}
              </p>
            </div>

            {/* Learning objectives */}
            {item.learningObjectives.length > 0 && (
              <div>
                <h5 className={`${copilotTextSizes.small} ${copilotColors.muted} font-medium mb-2`}>
                  What you&apos;ll learn:
                </h5>
                <ul className="space-y-1">
                  {item.learningObjectives.map((objective, idx) => (
                    <li 
                      key={idx} 
                      className={`flex items-start gap-2 ${copilotTextSizes.small} ${copilotColors.primary}`}
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-green-500 flex-shrink-0" />
                      {objective}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Evidence - Source segments */}
            {item.evidence.length > 0 && (
              <div>
                <h5 className={`${copilotTextSizes.small} ${copilotColors.muted} font-medium mb-2`}>
                  Key moments:
                </h5>
                <div className="space-y-2">
                  {item.evidence.slice(0, 3).map((ev, idx) => (
                    <a
                      key={idx}
                      href={ev.youTubeUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`block p-2 rounded-lg ${copilotColors.bg.primary} border ${copilotColors.border.default} ${copilotButtonStyles.interactive}`}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`${copilotTextSizes.xs} ${copilotColors.accent} font-mono`}>
                          {formatTimestamp(ev.timestampStart)}
                        </span>
                        <span className={`${copilotTextSizes.small} ${copilotColors.primary} line-clamp-2`}>
                          {ev.segmentText}
                        </span>
                        <ExternalLink className="w-3.5 h-3.5 text-[var(--copilot-kit-muted-color)] flex-shrink-0" />
                      </div>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Watch button */}
            <button
              className={`flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--copilot-kit-primary-color)] text-white ${copilotTextSizes.small} font-medium hover:opacity-90 transition-opacity`}
              onClick={(e) => {
                e.stopPropagation();
                onVideoClick?.(item.videoId);
              }}
            >
              <ExternalLink className="w-4 h-4" />
              Watch Video
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * LearningPathView - Displays a structured learning path with ordered videos
 * 
 * Features:
 * - Visual step-by-step ordering with connector lines
 * - Expandable items with rationale, objectives, and evidence
 * - Duration estimates and prerequisites
 * - Gap detection for missing content areas
 */
export function LearningPathView({ learningPath, onVideoClick }: LearningPathViewProps) {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="space-y-2">
        <h3 className={`${copilotTextSizes.header} ${copilotColors.primary}`}>
          {learningPath.title}
        </h3>
        <p className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
          {learningPath.description}
        </p>
        <div className="flex items-center gap-4">
          <span className={`flex items-center gap-1.5 ${copilotTextSizes.small} ${copilotColors.muted}`}>
            <Clock className="w-4 h-4" />
            Total: {formatDuration(learningPath.estimatedDuration)}
          </span>
          <span className={`flex items-center gap-1.5 ${copilotTextSizes.small} ${copilotColors.muted}`}>
            <BookOpen className="w-4 h-4" />
            {learningPath.items.length} video{learningPath.items.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* Learning path items */}
      <div className="space-y-3">
        {learningPath.items.map((item, index) => (
          <LearningPathItemCard
            key={item.videoId}
            item={item}
            isFirst={index === 0}
            isLast={index === learningPath.items.length - 1}
            onVideoClick={onVideoClick}
          />
        ))}
      </div>

      {/* Gaps - What's missing */}
      {learningPath.gaps.length > 0 && (
        <div className={`${copilotBoxStyles.static} mt-4`}>
          <h4 className={`flex items-center gap-2 ${copilotTextSizes.small} ${copilotColors.muted} font-medium mb-2`}>
            <AlertCircle className="w-4 h-4" />
            Topics not covered in your library:
          </h4>
          <ul className="flex flex-wrap gap-2">
            {learningPath.gaps.map((gap, idx) => (
              <li
                key={idx}
                className={`px-2 py-1 rounded-md ${copilotColors.bg.primary} border ${copilotColors.border.default} ${copilotTextSizes.small} ${copilotColors.primary}`}
              >
                {gap}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default LearningPathView;
