"use client";

import { HelpCircle } from "lucide-react";

interface WhyThisButtonProps {
  onClick: () => void;
  isExpanded: boolean;
  className?: string;
}

/**
 * "Why this?" button for video cards.
 * Toggles the explanation panel visibility.
 * US5 - Transparency feature.
 */
export function WhyThisButton({
  onClick,
  isExpanded,
  className = "",
}: WhyThisButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`
        inline-flex items-center gap-1
        text-xs font-medium
        text-gray-500 hover:text-red-600
        transition-colors
        ${isExpanded ? "text-red-600" : ""}
        ${className}
      `}
      aria-expanded={isExpanded}
      aria-label="Explain why this video was recommended"
    >
      <HelpCircle className="w-3.5 h-3.5" />
      <span>Why this?</span>
    </button>
  );
}
