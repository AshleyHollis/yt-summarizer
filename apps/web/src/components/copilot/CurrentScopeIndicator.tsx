"use client";

/**
 * @deprecated This component is deprecated. Use subcomponents/ScopeIndicator instead.
 * The refactored ThreadedCopilotSidebar uses CopilotKit's Custom Sub-Components pattern
 * which includes the ScopeIndicator directly in the CustomHeader component.
 * 
 * This file is kept for backward compatibility with the old ThreadedCopilotSidebar.tsx
 */

import { useVideoContext, useScope } from "@/app/providers";
import { MagnifyingGlassIcon, ArrowsPointingOutIcon, FilmIcon, FolderOpenIcon } from "@heroicons/react/20/solid";

interface CurrentScopeIndicatorProps {
  /** Called when user clicks to broaden search to entire library */
  onBroadenScope?: () => void;
  /** Called when user clicks to narrow search to current video */
  onNarrowToVideo?: () => void;
  /** Compact mode for smaller displays */
  compact?: boolean;
}

/**
 * CurrentScopeIndicator Component
 * 
 * Displays the current search scope to the user so they understand
 * what context the AI is working within. Provides quick actions to
 * broaden or narrow the search scope.
 * 
 * Scenarios:
 * 1. On video detail page with no scope set → Shows "This video: [title]"
 * 2. On video detail page with scope set → Shows scope chips
 * 3. On library page with no scope → Shows "Entire Library"
 * 4. On library page with scope → Shows scope chips
 * 
 * @see ThreadedCopilotSidebar.tsx - Parent component
 * @see providers.tsx - Context providers for scope and video
 */
export function CurrentScopeIndicator({
  onBroadenScope,
  onNarrowToVideo,
  compact = false,
}: CurrentScopeIndicatorProps) {
  const { currentVideo } = useVideoContext();
  const { scope, clearScope, setScope } = useScope();

  // Check if we have any scope restrictions
  const hasScope =
    (scope.channels && scope.channels.length > 0) ||
    (scope.videoIds && scope.videoIds.length > 0) ||
    (scope.facets && scope.facets.length > 0) ||
    scope.dateRange?.from ||
    scope.dateRange?.to;

  // Check if scope is set to the current video
  const isScopedToCurrentVideo =
    currentVideo &&
    scope.videoIds?.length === 1 &&
    scope.videoIds[0] === currentVideo.videoId;

  // Handle broadening scope to entire library
  const handleBroadenScope = () => {
    clearScope();
    onBroadenScope?.();
  };

  // Handle narrowing scope to current video
  const handleNarrowToVideo = () => {
    if (currentVideo) {
      setScope({ videoIds: [currentVideo.videoId] });
      onNarrowToVideo?.();
    }
  };

  // Determine what to show based on context
  const getScopeDisplay = () => {
    if (hasScope) {
      // Has specific scope filters
      if (isScopedToCurrentVideo) {
        return {
          icon: FilmIcon,
          label: "This video",
          detail: currentVideo?.title || "Current video",
          isNarrow: true,
        };
      }
      // Other scope (channels, facets, etc.)
      const parts: string[] = [];
      if (scope.channels?.length) {
        parts.push(`${scope.channels.length} channel${scope.channels.length > 1 ? "s" : ""}`);
      }
      if (scope.videoIds?.length) {
        parts.push(`${scope.videoIds.length} video${scope.videoIds.length > 1 ? "s" : ""}`);
      }
      if (scope.facets?.length) {
        parts.push(`${scope.facets.length} tag${scope.facets.length > 1 ? "s" : ""}`);
      }
      return {
        icon: MagnifyingGlassIcon,
        label: "Filtered search",
        detail: parts.join(", ") || "Custom scope",
        isNarrow: true,
      };
    }

    if (currentVideo) {
      // On video page but searching entire library
      return {
        icon: FolderOpenIcon,
        label: "Entire library",
        detail: "All indexed videos",
        isNarrow: false,
        showNarrowOption: true,
      };
    }

    // On library page, no scope
    return {
      icon: FolderOpenIcon,
      label: "Entire library",
      detail: "All indexed videos",
      isNarrow: false,
    };
  };

  const display = getScopeDisplay();
  const IconComponent = display.icon;

  if (compact) {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <IconComponent className="h-3.5 w-3.5 text-[var(--copilot-kit-muted-color)]" />
        <span className="text-[var(--copilot-kit-muted-color)] truncate max-w-[150px]">
          {display.label}
        </span>
        {display.isNarrow && (
          <button
            onClick={handleBroadenScope}
            className="flex items-center gap-0.5 text-[var(--copilot-kit-primary-color)] hover:underline"
            title="Search entire library"
          >
            <ArrowsPointingOutIcon className="h-3 w-3" />
            <span className="sr-only">Broaden</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="relative z-10 flex items-center justify-between gap-2 px-3 py-2 bg-[var(--copilot-kit-secondary-color)] border-b border-[var(--copilot-kit-separator-color)]">
      <div className="flex items-center gap-2 min-w-0">
        <IconComponent className="h-4 w-4 flex-shrink-0 text-[var(--copilot-kit-muted-color)]" />
        <div className="flex flex-col min-w-0">
          <span className="text-xs font-medium text-[var(--copilot-kit-secondary-contrast-color)]">
            {display.label}
          </span>
          <span className="text-xs text-[var(--copilot-kit-muted-color)] truncate">
            {display.detail}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-1">
        {display.isNarrow && (
          <button
            onClick={handleBroadenScope}
            className="flex items-center gap-1 px-2 py-1 text-xs rounded-md bg-[var(--copilot-kit-background-color)] border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] text-[var(--copilot-kit-secondary-contrast-color)] hover:text-[var(--copilot-kit-primary-color)] transition-colors"
            title="Search entire library instead"
          >
            <ArrowsPointingOutIcon className="h-3 w-3" />
            <span>Search All</span>
          </button>
        )}
        {display.showNarrowOption && currentVideo && (
          <button
            onClick={handleNarrowToVideo}
            className="flex items-center gap-1 px-2 py-1 text-xs rounded-md bg-[var(--copilot-kit-background-color)] border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] text-[var(--copilot-kit-secondary-contrast-color)] hover:text-[var(--copilot-kit-primary-color)] transition-colors"
            title="Search only this video"
          >
            <FilmIcon className="h-3 w-3" />
            <span>This Video Only</span>
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * ScopeSuggestionBanner Component
 * 
 * Shows when the copilot couldn't find relevant content and suggests
 * broadening the search scope. This is shown inline with the uncertainty
 * message.
 */
interface ScopeSuggestionBannerProps {
  /** The current video context (if on a video page) */
  currentVideoTitle?: string;
  /** Whether we're currently scoped to a specific video/subset */
  isNarrowScope: boolean;
  /** Called when user wants to search entire library */
  onSearchAll: () => void;
  /** The original query to retry */
  query?: string;
}

export function ScopeSuggestionBanner({
  currentVideoTitle,
  isNarrowScope,
  onSearchAll,
  query,
}: ScopeSuggestionBannerProps) {
  if (!isNarrowScope) {
    return null;
  }

  return (
    <div className="mt-3 p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700/50">
      <p className="text-sm text-blue-800 dark:text-blue-200">
        {currentVideoTitle ? (
          <>
            I searched only in &ldquo;{currentVideoTitle}&rdquo;.
            Would you like me to search your entire library?
          </>
        ) : (
          <>
            Your search was limited to a subset of videos.
            Would you like to search your entire library?
          </>
        )}
      </p>
      <button
        onClick={onSearchAll}
        className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
      >
        <ArrowsPointingOutIcon className="h-4 w-4" />
        Search Entire Library
        {query && <span className="text-red-200 text-xs ml-1">for &ldquo;{query.slice(0, 30)}...&rdquo;</span>}
      </button>
    </div>
  );
}
