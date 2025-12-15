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
    <div className="flex flex-wrap gap-2 mt-3">
      {suggestions.slice(0, 3).map((suggestion, index) => (
        <button
          key={index}
          onClick={() => onFollowupClick(suggestion)}
          className="inline-flex items-center rounded-full bg-gray-100 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-200 transition-colors"
        >
          {suggestion}
        </button>
      ))}
    </div>
  );
}
