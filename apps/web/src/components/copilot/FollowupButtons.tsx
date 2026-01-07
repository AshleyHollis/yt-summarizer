"use client";

interface FollowupButtonsProps {
  suggestions: string[];
  onFollowupClick: (suggestion: string) => void;
}

export function FollowupButtons({
  suggestions,
  onFollowupClick,
}: FollowupButtonsProps) {
  if (!suggestions || suggestions.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3 bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150">
      <p className="text-sm font-semibold text-[var(--copilot-kit-secondary-contrast-color)] flex items-center gap-2">
        <svg className="w-4 h-4 text-[var(--copilot-kit-primary-color)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        Follow-up questions
      </p>
      <div className="flex flex-col gap-2">
        {suggestions.slice(0, 3).map((suggestion, index) => (
          <button
            key={index}
            onClick={() => onFollowupClick(suggestion)}
            className="group flex items-start gap-3 rounded-lg border border-[var(--copilot-kit-separator-color)] bg-[var(--copilot-kit-background-color)] px-3 py-3 text-sm text-[var(--copilot-kit-secondary-contrast-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150 cursor-pointer text-left"
          >
            <span className="text-[var(--copilot-kit-primary-color)] shrink-0 pt-0.5 text-sm font-semibold">→</span>
            <span className="flex-1 line-clamp-2 leading-relaxed">{suggestion}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
