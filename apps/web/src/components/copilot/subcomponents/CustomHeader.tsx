"use client";

/**
 * CustomHeader - CopilotKit Custom Sub-Component
 *
 * This is the CopilotKit-sanctioned way to customize the chat header.
 * Instead of fighting CSS with position:absolute overrides, we pass this
 * component to CopilotSidebar's Header prop.
 *
 * Includes:
 * - Title and branding
 * - Thread selection dropdown
 * - Scope indicator (what context AI is searching)
 * - Size controls and close button
 *
 * @see https://docs.copilotkit.ai/custom-look-and-feel/bring-your-own-components
 */

import { MessageCircle, MessageSquare, ChevronDown, ChevronUp, Plus, X, Maximize2, Minimize2, Square, Columns2 } from "lucide-react";
import { useRef, useEffect } from "react";
import { ThreadList, Thread } from "../ThreadList";
import { ScopeIndicator } from "./ScopeIndicator";

type SizeMode = "compact" | "default" | "half" | "full";

interface CustomHeaderProps {
  /** List of chat threads */
  threads: Thread[];
  /** Currently active thread ID */
  activeThreadId: string | null;
  /** Title of the active thread */
  activeThreadTitle: string;
  /** Whether threads dropdown is collapsed */
  threadsCollapsed: boolean;
  /** Toggle threads dropdown */
  onToggleThreads: () => void;
  /** Start a new chat */
  onNewChat: () => void;
  /** Select a thread */
  onSelectThread: (threadId: string) => void;
  /** Delete a thread */
  onDeleteThread: (threadId: string) => void;
  /** Close the sidebar */
  onClose: () => void;
  /** Current size mode */
  sizeMode: SizeMode;
  /** Cycle through size modes */
  onCycleSize: () => void;
  /** Whether on mobile */
  isMobile: boolean;
}

const SIZE_CONFIG: Record<SizeMode, { label: string }> = {
  compact: { label: "Compact (20%)" },
  default: { label: "Default (30%)" },
  half: { label: "Half screen (50%)" },
  full: { label: "Full screen" },
};

const SIZE_MODES: SizeMode[] = ["compact", "default", "half", "full"];

export function CustomHeader({
  threads,
  activeThreadId,
  activeThreadTitle,
  threadsCollapsed,
  onToggleThreads,
  onNewChat,
  onSelectThread,
  onDeleteThread,
  onClose,
  sizeMode,
  onCycleSize,
  isMobile,
}: CustomHeaderProps) {
  const threadsDropdownRef = useRef<HTMLDivElement>(null);

  // Close threads dropdown on outside click
  useEffect(() => {
    if (threadsCollapsed) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (threadsDropdownRef.current && !threadsDropdownRef.current.contains(event.target as Node)) {
        onToggleThreads();
      }
    };

    const timeoutId = setTimeout(() => {
      document.addEventListener("mousedown", handleClickOutside);
    }, 0);

    return () => {
      clearTimeout(timeoutId);
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [threadsCollapsed, onToggleThreads]);

  const getSizeIcon = () => {
    switch (sizeMode) {
      case "compact": return <Maximize2 className="w-4 h-4" />;
      case "default": return <Columns2 className="w-4 h-4" />;
      case "half": return <Square className="w-4 h-4" />;
      case "full": return <Minimize2 className="w-4 h-4" />;
    }
  };

  const getSizeTooltip = () => {
    const currentIndex = SIZE_MODES.indexOf(sizeMode);
    const nextIndex = (currentIndex + 1) % SIZE_MODES.length;
    return SIZE_CONFIG[SIZE_MODES[nextIndex]].label;
  };

  return (
    <div className="flex flex-col border-b border-[var(--copilot-kit-separator-color)] bg-[var(--copilot-kit-background-color)]">
      {/* Main header row */}
      <div className="h-10 flex items-center justify-between gap-2 px-2">
        {/* Logo & Title */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <div className="w-6 h-6 rounded-md bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center">
            <MessageCircle className="w-3 h-3 text-white" />
          </div>
          <span className="text-base font-semibold leading-none text-[var(--copilot-kit-secondary-contrast-color)]">
            AI Assistant
          </span>
        </div>

        {/* Thread controls */}
        <div ref={threadsDropdownRef} className="relative flex-1 min-w-0">
          <div className="flex items-center gap-1.5 min-w-0 w-full">
            <button
              onClick={onToggleThreads}
              className="group flex flex-1 items-center gap-1.5 min-w-0 w-full border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-secondary-color)] rounded-lg px-2 py-1.5 transition-all duration-150"
              title={threadsCollapsed ? "Show all threads" : "Hide threads"}
            >
              <MessageSquare className="w-3.5 h-3.5 text-[var(--copilot-kit-muted-color)] group-hover:text-[var(--copilot-kit-primary-color)] flex-shrink-0 transition-colors" />
              <span className="text-sm font-medium leading-none text-[var(--copilot-kit-secondary-contrast-color)] overflow-hidden text-ellipsis whitespace-nowrap flex-1 text-left">
                {activeThreadTitle}
              </span>
              {threadsCollapsed ? (
                <ChevronDown className="w-3.5 h-3.5 text-[var(--copilot-kit-muted-color)] group-hover:text-[var(--copilot-kit-primary-color)] flex-shrink-0 ml-auto transition-colors" />
              ) : (
                <ChevronUp className="w-3.5 h-3.5 text-[var(--copilot-kit-muted-color)] group-hover:text-[var(--copilot-kit-primary-color)] flex-shrink-0 ml-auto transition-colors" />
              )}
            </button>
            <button
              onClick={onNewChat}
              className="p-1.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-secondary-color)] text-[var(--copilot-kit-primary-color)] flex-shrink-0 transition-all duration-150"
              title="New chat"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>

          {/* Threads dropdown */}
          {!threadsCollapsed && (
            <ThreadList
              threads={threads}
              activeThreadId={activeThreadId}
              onSelectThread={onSelectThread}
              onDeleteThread={onDeleteThread}
              onClose={onToggleThreads}
            />
          )}
        </div>

        {/* Size & Close buttons */}
        <div className="flex items-center gap-1 flex-shrink-0">
          {!isMobile && (
            <button
              onClick={onCycleSize}
              className="p-1.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-secondary-color)] text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-primary-color)] transition-all duration-150"
              title={getSizeTooltip()}
            >
              {getSizeIcon()}
            </button>
          )}
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-secondary-color)] text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-primary-color)] transition-all duration-150"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scope indicator row */}
      <ScopeIndicator />
    </div>
  );
}
