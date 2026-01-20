'use client';

import React from 'react';

interface DescriptionRendererProps {
  /** Raw description text */
  content: string;
  /** Additional CSS classes */
  className?: string;
}

/**
 * Converts URLs in text to clickable links
 */
function linkifyText(text: string): React.ReactNode[] {
  // Regex to match URLs
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`[\]]+)/g;
  const parts = text.split(urlRegex);

  return parts.map((part, index) => {
    if (urlRegex.test(part)) {
      // Reset lastIndex after test
      urlRegex.lastIndex = 0;
      return (
        <a
          key={index}
          href={part}
          target="_blank"
          rel="noopener noreferrer"
          className="text-red-600 dark:text-red-400 hover:underline break-all"
        >
          {part}
        </a>
      );
    }
    return part;
  });
}

/**
 * Parses YouTube description text and renders it with proper formatting
 * - Converts URLs to clickable links
 * - Preserves line breaks
 * - Handles emoji characters properly
 */
export function DescriptionRenderer({ content, className = '' }: DescriptionRendererProps) {
  // Split by newlines and process each line
  const lines = content.split('\n');

  return (
    <div className={`text-sm text-gray-700 dark:text-gray-300 leading-relaxed ${className}`}>
      {lines.map((line, lineIndex) => (
        <React.Fragment key={lineIndex}>
          {line.length > 0 ? <span>{linkifyText(line)}</span> : <br />}
          {lineIndex < lines.length - 1 && line.length > 0 && <br />}
        </React.Fragment>
      ))}
    </div>
  );
}

export default DescriptionRenderer;
