"use client";

import { ReactNode } from "react";

interface ToolLoadingStateProps {
  /** Primary loading message */
  title: string;
  /** Secondary description */
  description?: string;
  /** Optional custom icon (defaults to spinner) */
  icon?: ReactNode;
}

/**
 * Reusable loading state component for tool execution.
 * 
 * Used by both frontend tools (Pattern A) and backend tool renderers (Pattern B)
 * to provide consistent loading UI during tool execution.
 */
export function ToolLoadingState({ title, description }: ToolLoadingStateProps) {
  return (
    <div className="flex items-center gap-3 py-3 px-4 bg-[var(--copilot-kit-secondary-color)]/80 rounded-xl border border-[var(--copilot-kit-separator-color)] animate-pulse">
      <div className="relative flex-shrink-0">
        <div className="w-5 h-5 border-2 border-[var(--copilot-kit-separator-color)] border-t-[var(--copilot-kit-primary-color)] rounded-full animate-spin" />
      </div>
      <div className="flex-1 min-w-0">
        <span className="text-sm font-medium text-[var(--copilot-kit-secondary-contrast-color)]">
          {title}
        </span>
        {description && (
          <p className="text-xs text-[var(--copilot-kit-muted-color)] mt-0.5 truncate">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * Check if tool is in a loading state
 */
export function isToolLoading(status: string): boolean {
  return status === "inProgress" || status === "executing";
}

/**
 * Check if tool is complete
 */
export function isToolComplete(status: string): boolean {
  return status === "complete";
}
