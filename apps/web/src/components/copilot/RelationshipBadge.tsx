'use client';

import { Link2, Layers } from 'lucide-react';

interface RelationshipBadgeProps {
  relatedTo: string;
  className?: string;
}

/**
 * Badge showing relationship context for a recommended video.
 * Displays series/related info like "Part of the Kettlebell Fundamentals series".
 * US5 - Transparency feature.
 */
export function RelationshipBadge({ relatedTo, className = '' }: RelationshipBadgeProps) {
  if (!relatedTo) {
    return null;
  }

  // Determine icon based on relationship content
  const isSeries =
    relatedTo.toLowerCase().includes('series') || relatedTo.toLowerCase().includes('part');
  const Icon = isSeries ? Layers : Link2;

  return (
    <div
      data-testid="relationship-badge"
      className={`
        inline-flex items-center gap-1.5
        px-2 py-1
        bg-purple-50 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300
        text-xs font-medium
        rounded-full
        ${className}
      `}
    >
      <Icon className="w-3 h-3" />
      <span>{relatedTo}</span>
    </div>
  );
}
