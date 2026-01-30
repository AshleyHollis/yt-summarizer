"use client";

import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Star,
  Tag,
  ExternalLink,
  AlertCircle,
  ArrowUp,
  ArrowRight,
  ArrowDown,
} from "lucide-react";
import { copilotBoxStyles, copilotTextSizes, copilotColors } from "./copilotStyles";
import { formatDuration } from "@/utils/formatDuration";

/**
 * Priority levels for watch list items
 */
type Priority = "high" | "medium" | "low";

/**
 * Individual item in a watch list
 */
interface WatchListItem {
  videoId: string;
  title: string;
  description: string;
  priority: Priority;
  reason: string;
  estimatedDuration: number;
  tags: string[];
}

/**
 * Complete watch list structure
 */
interface WatchList {
  title: string;
  description: string;
  totalDuration: number;
  items: WatchListItem[];
  gaps: string[];
}

interface WatchListViewProps {
  watchList: WatchList;
  onVideoClick?: (videoId: string) => void;
}

/**
 * Get priority styling based on priority level
 */
function getPriorityConfig(priority: Priority): {
  icon: React.ReactNode;
  label: string;
  bgClass: string;
  textClass: string;
} {
  switch (priority) {
    case "high":
      return {
        icon: <ArrowUp className="w-3.5 h-3.5" />,
        label: "High Priority",
        bgClass: "bg-red-100 dark:bg-red-900/30",
        textClass: "text-red-600 dark:text-red-400",
      };
    case "medium":
      return {
        icon: <ArrowRight className="w-3.5 h-3.5" />,
        label: "Medium Priority",
        bgClass: "bg-yellow-100 dark:bg-yellow-900/30",
        textClass: "text-yellow-600 dark:text-yellow-400",
      };
    case "low":
      return {
        icon: <ArrowDown className="w-3.5 h-3.5" />,
        label: "Low Priority",
        bgClass: "bg-green-100 dark:bg-green-900/30",
        textClass: "text-green-600 dark:text-green-400",
      };
  }
}

/**
 * Component for displaying a single watch list item
 */
function WatchListItemCard({
  item,
  onVideoClick,
}: {
  item: WatchListItem;
  onVideoClick?: (videoId: string) => void;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const priorityConfig = getPriorityConfig(item.priority);

  return (
    <div
      className={`${copilotBoxStyles.full} cursor-pointer`}
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
        {/* Priority indicator */}
        <div
          className={`flex-shrink-0 px-2 py-1 rounded-md flex items-center gap-1 ${priorityConfig.bgClass} ${priorityConfig.textClass} ${copilotTextSizes.xs} font-medium`}
          title={priorityConfig.label}
        >
          {priorityConfig.icon}
          <span className="hidden sm:inline">{item.priority.charAt(0).toUpperCase() + item.priority.slice(1)}</span>
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

          <div className="flex items-center gap-3 flex-wrap">
            <span className={`flex items-center gap-1 ${copilotTextSizes.small} ${copilotColors.muted}`}>
              <Clock className="w-3.5 h-3.5" />
              {formatDuration(item.estimatedDuration)}
            </span>
            {item.tags.length > 0 && (
              <div className="flex items-center gap-1">
                <Tag className={`w-3.5 h-3.5 ${copilotColors.muted}`} />
                <span className={`${copilotTextSizes.small} ${copilotColors.muted}`}>
                  {item.tags.slice(0, 3).join(", ")}
                  {item.tags.length > 3 && ` +${item.tags.length - 3}`}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="mt-4 ml-0 sm:ml-14 space-y-4">
          {/* Description */}
          <p className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
            {item.description}
          </p>

          {/* Reason - Why this recommendation */}
          <div className={`p-3 rounded-lg ${copilotColors.bg.primary} border ${copilotColors.border.default}`}>
            <h5 className={`${copilotTextSizes.small} ${copilotColors.accent} font-medium mb-1 flex items-center gap-1.5`}>
              <Star className="w-3.5 h-3.5" />
              Why we recommend this
            </h5>
            <p className={`${copilotTextSizes.small} ${copilotColors.primary}`}>
              {item.reason}
            </p>
          </div>

          {/* Tags - full list */}
          {item.tags.length > 0 && (
            <div>
              <h5 className={`${copilotTextSizes.small} ${copilotColors.muted} font-medium mb-2`}>
                Topics covered:
              </h5>
              <div className="flex flex-wrap gap-1.5">
                {item.tags.map((tag, idx) => (
                  <span
                    key={idx}
                    className={`px-2 py-0.5 rounded-full ${copilotColors.bg.primary} border ${copilotColors.border.default} ${copilotTextSizes.xs} ${copilotColors.primary}`}
                  >
                    {tag}
                  </span>
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
  );
}

/**
 * WatchListView - Displays a prioritized watch list of recommended videos
 *
 * Features:
 * - Priority-based visual indicators (high/medium/low)
 * - Expandable items with reasons and tags
 * - Duration estimates and topic tags
 * - Gap detection for missing content areas
 */
export function WatchListView({ watchList, onVideoClick }: WatchListViewProps) {
  // Group items by priority for visual organization
  const highPriority = watchList.items.filter(item => item.priority === "high");
  const mediumPriority = watchList.items.filter(item => item.priority === "medium");
  const lowPriority = watchList.items.filter(item => item.priority === "low");

  const priorityGroups = [
    { priority: "high" as Priority, items: highPriority },
    { priority: "medium" as Priority, items: mediumPriority },
    { priority: "low" as Priority, items: lowPriority },
  ].filter(group => group.items.length > 0);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="space-y-2">
        <h3 className={`${copilotTextSizes.header} ${copilotColors.primary}`}>
          {watchList.title}
        </h3>
        <p className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
          {watchList.description}
        </p>
        <div className="flex items-center gap-4">
          <span className={`flex items-center gap-1.5 ${copilotTextSizes.small} ${copilotColors.muted}`}>
            <Clock className="w-4 h-4" />
            Total: {formatDuration(watchList.totalDuration)}
          </span>
          <span className={`flex items-center gap-1.5 ${copilotTextSizes.small} ${copilotColors.muted}`}>
            <Star className="w-4 h-4" />
            {watchList.items.length} video{watchList.items.length !== 1 ? "s" : ""}
          </span>
          {highPriority.length > 0 && (
            <span className={`flex items-center gap-1.5 ${copilotTextSizes.small} text-red-500`}>
              <ArrowUp className="w-4 h-4" />
              {highPriority.length} high priority
            </span>
          )}
        </div>
      </div>

      {/* Watch list items grouped by priority */}
      <div className="space-y-4">
        {priorityGroups.map(group => (
          <div key={group.priority} className="space-y-2">
            <h4 className={`${copilotTextSizes.small} ${copilotColors.muted} font-medium uppercase tracking-wide`}>
              {group.priority} Priority
            </h4>
            <div className="space-y-2">
              {group.items.map(item => (
                <WatchListItemCard
                  key={item.videoId}
                  item={item}
                  onVideoClick={onVideoClick}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Gaps - What's missing */}
      {watchList.gaps.length > 0 && (
        <div className={`${copilotBoxStyles.static} mt-4`}>
          <h4 className={`flex items-center gap-2 ${copilotTextSizes.small} ${copilotColors.muted} font-medium mb-2`}>
            <AlertCircle className="w-4 h-4" />
            Topics not covered in your library:
          </h4>
          <ul className="flex flex-wrap gap-2">
            {watchList.gaps.map((gap, idx) => (
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

export default WatchListView;
