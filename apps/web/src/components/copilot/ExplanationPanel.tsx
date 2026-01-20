'use client';

import { Lightbulb } from 'lucide-react';
import { KeyMomentsList } from './KeyMomentsList';
import { RelationshipBadge } from './RelationshipBadge';

interface KeyMoment {
  timestamp: string;
  description: string;
  segmentId?: string | null;
  youTubeUrl?: string | null;
}

interface VideoExplanation {
  summary: string;
  keyMoments: KeyMoment[];
  relatedTo?: string | null;
}

interface ExplanationPanelProps {
  explanation: VideoExplanation;
  className?: string;
}

/**
 * Panel displaying why a video was recommended.
 * Shows a focused explanation of relevance to the user's query.
 * Only rendered when there's meaningful LLM-generated content.
 * Displayed inline when user clicks "Why this?" - no API call needed.
 * US5 - Transparency feature.
 */
export function ExplanationPanel({ explanation, className = '' }: ExplanationPanelProps) {
  const hasKeyMoments = explanation.keyMoments && explanation.keyMoments.length > 0;
  const hasRelationship = !!explanation.relatedTo;

  return (
    <div
      data-testid="explanation-panel"
      className={`
        mt-3 p-3
        bg-gradient-to-r from-red-50 to-rose-50 dark:from-red-900/20 dark:to-rose-900/20
        border border-red-200/60 dark:border-red-700/40 rounded-lg
        animate-in slide-in-from-top-2 duration-200
        ${className}
      `}
    >
      {/* Summary - the core explanation */}
      <div className="flex items-start gap-2">
        <Lightbulb className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0" />
        <p className="text-sm text-gray-800 dark:text-gray-200 leading-relaxed">
          {explanation.summary}
        </p>
      </div>

      {/* Relationship badge - if this is related to another video */}
      {hasRelationship && (
        <div className="mt-2 ml-6">
          <RelationshipBadge relatedTo={explanation.relatedTo!} />
        </div>
      )}

      {/* Key moments - only show if we have meaningful ones */}
      {hasKeyMoments && (
        <div className="mt-3 ml-6">
          <KeyMomentsList moments={explanation.keyMoments} />
        </div>
      )}
    </div>
  );
}
