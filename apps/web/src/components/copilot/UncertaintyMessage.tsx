"use client";

import { ExclamationTriangleIcon, ArrowsPointingOutIcon } from "@heroicons/react/20/solid";

interface UncertaintyMessageProps {
  message: string;
  /** Show option to broaden search scope */
  showBroadenOption?: boolean;
  /** Current video title if scoped to a video */
  currentVideoTitle?: string;
  /** Callback when user wants to search entire library */
  onBroadenScope?: () => void;
}

/**
 * UncertaintyMessage Component
 * 
 * Displays a message when the AI has limited information to answer.
 * Optionally shows a "Search Entire Library" button when the search
 * was scoped to a specific video or subset.
 * 
 * This helps users understand WHY they're not getting results and
 * gives them an actionable way to broaden their search.
 */
export function UncertaintyMessage({
  message,
  showBroadenOption = false,
  currentVideoTitle,
  onBroadenScope,
}: UncertaintyMessageProps) {
  return (
    <div className="rounded-xl bg-[var(--copilot-kit-secondary-color)] border border-amber-500/40 p-4 animate-in fade-in duration-200">
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0 p-2 bg-amber-500/15 rounded-lg border border-amber-500/20">
          <ExclamationTriangleIcon className="h-4 w-4 text-amber-500" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-amber-500">
            Limited Information
          </p>
          <p className="text-sm text-[var(--copilot-kit-secondary-contrast-color)] leading-relaxed mt-1">
            {message}
          </p>
          
          {/* Scope suggestion when results are limited */}
          {showBroadenOption && onBroadenScope && (
            <div className="mt-3 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
              <p className="text-sm text-[var(--copilot-kit-secondary-contrast-color)]">
                {currentVideoTitle ? (
                  <>
                    I only searched within &ldquo;<span className="font-medium">{currentVideoTitle}</span>&rdquo;.
                  </>
                ) : (
                  <>Your search was limited to a subset of your library.</>
                )}
              </p>
              <button
                onClick={onBroadenScope}
                className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
              >
                <ArrowsPointingOutIcon className="h-4 w-4" />
                Search Entire Library
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
