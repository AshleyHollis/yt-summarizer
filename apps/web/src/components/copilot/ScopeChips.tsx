'use client';

import { useScope } from '@/app/providers';
import { XMarkIcon } from '@heroicons/react/20/solid';

interface ScopeChipsProps {
  onScopeChange?: () => void;
}

export function ScopeChips({ onScopeChange }: ScopeChipsProps) {
  const { scope, removeChannel, removeVideo, removeFacet, clearScope } = useScope();

  const hasScope =
    (scope.channels && scope.channels.length > 0) ||
    (scope.videoIds && scope.videoIds.length > 0) ||
    (scope.facets && scope.facets.length > 0) ||
    scope.dateRange?.from ||
    scope.dateRange?.to;

  if (!hasScope) {
    return <div className="text-sm text-gray-500">Searching entire library</div>;
  }

  return (
    <div className="flex flex-wrap gap-1">
      {/* Channel chips */}
      {scope.channels?.map((channelId) => (
        <Chip
          key={`channel-${channelId}`}
          label={`Channel: ${channelId.slice(0, 8)}...`}
          onRemove={() => {
            removeChannel(channelId);
            onScopeChange?.();
          }}
          color="blue"
        />
      ))}

      {/* Video chips */}
      {scope.videoIds?.map((videoId) => (
        <Chip
          key={`video-${videoId}`}
          label={`Video: ${videoId.slice(0, 8)}...`}
          onRemove={() => {
            removeVideo(videoId);
            onScopeChange?.();
          }}
          color="green"
        />
      ))}

      {/* Facet chips */}
      {scope.facets?.map((facetId) => (
        <Chip
          key={`facet-${facetId}`}
          label={`Tag: ${facetId.slice(0, 8)}...`}
          onRemove={() => {
            removeFacet(facetId);
            onScopeChange?.();
          }}
          color="purple"
        />
      ))}

      {/* Date range chip */}
      {(scope.dateRange?.from || scope.dateRange?.to) && (
        <Chip
          label={`${scope.dateRange.from || '...'} to ${scope.dateRange.to || '...'}`}
          onRemove={() => {
            // Would need updateScope for this
            onScopeChange?.();
          }}
          color="orange"
        />
      )}

      {/* Clear all button */}
      {hasScope && (
        <button
          onClick={() => {
            clearScope();
            onScopeChange?.();
          }}
          className="text-xs text-gray-500 hover:text-gray-700 underline ml-2"
        >
          Clear all
        </button>
      )}
    </div>
  );
}

interface ChipProps {
  label: string;
  onRemove: () => void;
  color: 'blue' | 'green' | 'purple' | 'orange';
}

function Chip({ label, onRemove, color }: ChipProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-800',
    green: 'bg-green-100 text-green-800',
    purple: 'bg-purple-100 text-purple-800',
    orange: 'bg-orange-100 text-orange-800',
  };

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${colorClasses[color]}`}
    >
      {label}
      <button onClick={onRemove} className="hover:bg-black/10 rounded-full p-0.5">
        <XMarkIcon className="h-3 w-3" />
      </button>
    </span>
  );
}
