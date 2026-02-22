"use client";

/**
 * ScopeIndicator - Shows what context and knowledge sources the AI can use
 *
 * Provides controls for:
 * 1. Search scope - Where to search for video context (All/Channel/Video)
 * 2. Knowledge sources - What the AI can draw from:
 *    - Video Library (RAG context from indexed videos)
 *    - AI Knowledge (LLM's trained knowledge)
 *    - Web Search (real-time web search results)
 *
 * The scope control adapts based on context - on library pages only "All" is shown,
 * on video pages all three options are available.
 */

import { useVideoContext, useScope, useAISettings } from "@/app/providers";
import {
  FolderOpenIcon,
  FilmIcon,
  UsersIcon,
  LightBulbIcon,
  GlobeAltIcon,
  BookOpenIcon,
  InformationCircleIcon,
  RectangleStackIcon,
  XMarkIcon
} from "@heroicons/react/20/solid";
import { useState } from "react";

type ScopeLevel = "library" | "channel" | "video" | "selected";

export function ScopeIndicator() {
  const { currentVideo } = useVideoContext();
  const { scope, clearScope, setScope } = useScope();
  const { settings, toggleSetting } = useAISettings();
  const [showHelp, setShowHelp] = useState(false);

  // Determine current scope level
  const getCurrentScopeLevel = (): ScopeLevel => {
    // Check if there are multiple selected videos (from library selection)
    if (scope.videoIds && scope.videoIds.length > 1) {
      return "selected";
    }
    if (
      currentVideo &&
      scope.videoIds?.length === 1 &&
      scope.videoIds[0] === currentVideo.videoId
    ) {
      return "video";
    }
    if (
      currentVideo &&
      scope.channels?.length === 1 &&
      scope.channels[0] === currentVideo.channelName &&
      !scope.videoIds?.length
    ) {
      return "channel";
    }
    // Also check for single video selection without currentVideo context
    if (scope.videoIds?.length === 1 && !currentVideo) {
      return "selected";
    }
    return "library";
  };

  const currentLevel = getCurrentScopeLevel();

  // Handle scope change
  const handleScopeChange = (level: ScopeLevel) => {
    if (level === currentLevel) return;

    switch (level) {
      case "library":
        clearScope();
        break;
      case "channel":
        if (currentVideo) {
          setScope({ channels: [currentVideo.channelName] });
        }
        break;
      case "video":
        if (currentVideo) {
          setScope({ videoIds: [currentVideo.videoId] });
        }
        break;
    }
  };

  // Scope options for segmented control
  const scopeOptions: { level: ScopeLevel; label: string; description: string; icon: typeof FolderOpenIcon }[] = [
    { level: "library", label: "All Videos", description: "Search your entire library", icon: FolderOpenIcon },
    { level: "channel", label: "This Channel", description: currentVideo ? `Only ${currentVideo.channelName}` : "Only this channel", icon: UsersIcon },
    { level: "video", label: "This Video", description: "Only the current video", icon: FilmIcon },
  ];

  // Knowledge source toggles with better descriptions
  const knowledgeSources = [
    {
      key: "useVideoContext" as const,
      label: "Your Videos",
      icon: BookOpenIcon,
      description: "Search transcripts & summaries from your library",
      shortDesc: "Library content"
    },
    {
      key: "useLLMKnowledge" as const,
      label: "AI Knowledge",
      icon: LightBulbIcon,
      description: "Include AI's general knowledge in answers",
      shortDesc: "General knowledge"
    },
    {
      key: "useWebSearch" as const,
      label: "Web Search",
      icon: GlobeAltIcon,
      description: "Search the web for current information",
      shortDesc: "Live web results"
    },
  ];

  return (
    <div className="relative flex flex-col gap-1 px-2 py-1.5 bg-[var(--copilot-kit-secondary-color)] border-b border-[var(--copilot-kit-separator-color)]">
      {/* Main controls row */}
      <div className="flex items-center gap-2">
        {/* Search scope section */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-[var(--copilot-kit-muted-color)] font-medium">Search:</span>
          {currentVideo ? (
            <div className="flex items-center bg-[var(--copilot-kit-background-color)] rounded p-0.5 border border-[var(--copilot-kit-separator-color)]">
              {scopeOptions.map(({ level, label, description, icon: Icon }) => {
                const isActive = currentLevel === level;
                return (
                  <button
                    key={level}
                    onClick={() => handleScopeChange(level)}
                    className={`
                      flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] rounded transition-all
                      ${isActive
                        ? "bg-[var(--copilot-kit-primary-color)] text-white font-medium"
                        : "text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-secondary-contrast-color)] hover:bg-[var(--copilot-kit-background-color)]"
                      }
                    `}
                    title={description}
                  >
                    <Icon className="h-2.5 w-2.5" />
                    <span>{label}</span>
                  </button>
                );
              })}
            </div>
          ) : currentLevel === "selected" ? (
            // Show selected videos badge with clear option - styled to match segmented control buttons
            <div className="flex items-center bg-[var(--copilot-kit-background-color)] rounded p-0.5 border border-[var(--copilot-kit-separator-color)]">
              <button
                onClick={() => clearScope()}
                className="group/clear flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] rounded bg-[var(--copilot-kit-primary-color)] text-white font-medium hover:brightness-110 transition-all"
                title={`Searching ${scope.videoIds?.length} selected video${scope.videoIds && scope.videoIds.length !== 1 ? 's' : ''} - click to clear`}
              >
                <RectangleStackIcon className="h-2.5 w-2.5" />
                <span>{scope.videoIds?.length} Video{scope.videoIds && scope.videoIds.length !== 1 ? 's' : ''} Selected</span>
                <span className="inline-flex items-center justify-center ml-0.5 rounded-sm group-hover/clear:bg-white/20 transition-colors">
                  <XMarkIcon className="h-2.5 w-2.5" />
                </span>
              </button>
            </div>
          ) : (
            // All Videos badge - styled to match segmented control buttons
            <div className="flex items-center bg-[var(--copilot-kit-background-color)] rounded p-0.5 border border-[var(--copilot-kit-separator-color)]">
              <button
                className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] rounded bg-[var(--copilot-kit-primary-color)] text-white font-medium cursor-default"
                title="Search your entire video library"
              >
                <FolderOpenIcon className="h-2.5 w-2.5" />
                <span>All Videos</span>
              </button>
            </div>
          )}
        </div>

        {/* Divider */}
        <div className="w-px h-4 bg-[var(--copilot-kit-separator-color)]" />

        {/* Knowledge sources section */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-[var(--copilot-kit-muted-color)] font-medium">Include:</span>
          <div className="flex items-center bg-[var(--copilot-kit-background-color)] rounded p-0.5 border border-[var(--copilot-kit-separator-color)]">
            {knowledgeSources.map(({ key, label, icon: Icon, description }) => {
              const isActive = settings[key];
              return (
                <button
                  key={key}
                  onClick={() => toggleSetting(key)}
                  className={`
                    flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] rounded transition-all
                    ${isActive
                      ? "bg-[var(--copilot-kit-primary-color)] text-white font-medium"
                      : "text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-secondary-contrast-color)] hover:bg-[var(--copilot-kit-background-color)]"
                    }
                  `}
                  title={`${isActive ? "Disable" : "Enable"}: ${description}`}
                >
                  <Icon className="h-2.5 w-2.5" />
                  <span>{label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Help button */}
        <button
          onClick={() => setShowHelp(!showHelp)}
          className="ml-auto p-0.5 text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-secondary-contrast-color)] transition-colors"
          title="What do these options mean?"
        >
          <InformationCircleIcon className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Help panel - shows when help button is clicked */}
      {showHelp && (
        <div className="mt-1 p-2 bg-[var(--copilot-kit-background-color)] rounded border border-[var(--copilot-kit-separator-color)] text-[10px]">
          <div className="font-medium text-[var(--copilot-kit-secondary-contrast-color)] mb-1.5">How to customize AI responses:</div>
          <div className="space-y-1.5">
            <div>
              <span className="font-medium text-[var(--copilot-kit-secondary-contrast-color)]">Search:</span>
              <span className="text-[var(--copilot-kit-muted-color)]"> Choose which videos to search — all videos, just this channel, or only this video.</span>
            </div>
            <div>
              <span className="font-medium text-[var(--copilot-kit-secondary-contrast-color)]">Include:</span>
              <span className="text-[var(--copilot-kit-muted-color)]"> Toggle what the AI can use in its answers:</span>
              <ul className="mt-0.5 ml-3 space-y-0.5 text-[var(--copilot-kit-muted-color)]">
                <li>• <strong>{"Your Videos"}</strong> — Transcripts and summaries from your library</li>
                <li>• <strong>{"AI Knowledge"}</strong> — The AI&apos;s general training knowledge</li>
                <li>• <strong>{"Web Search"}</strong> — Live search results from the internet</li>
              </ul>
            </div>
          </div>
          <button
            onClick={() => setShowHelp(false)}
            className="mt-2 text-[var(--copilot-kit-primary-color)] hover:underline"
          >
            Got it
          </button>
        </div>
      )}
    </div>
  );
}
