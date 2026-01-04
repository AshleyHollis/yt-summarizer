'use client';

import { useEffect, useState } from 'react';
import { XMarkIcon } from '@heroicons/react/20/solid';
import type { FacetCount } from '@/services/api';
import { libraryApi } from '@/services/api';

interface FacetChipsProps {
  selectedFacets: string[];
  onFacetToggle: (facetId: string) => void;
  onClearFacets: () => void;
}

/**
 * Get facet type badge color
 */
function getFacetTypeColor(type: string): {
  bg: string;
  text: string;
  border: string;
} {
  switch (type) {
    case 'topic':
      return {
        bg: 'bg-indigo-50 dark:bg-indigo-900/30',
        text: 'text-indigo-700 dark:text-indigo-300',
        border: 'border-indigo-200 dark:border-indigo-700',
      };
    case 'format':
      return {
        bg: 'bg-purple-50 dark:bg-purple-900/30',
        text: 'text-purple-700 dark:text-purple-300',
        border: 'border-purple-200 dark:border-purple-700',
      };
    case 'level':
      return {
        bg: 'bg-orange-50 dark:bg-orange-900/30',
        text: 'text-orange-700 dark:text-orange-300',
        border: 'border-orange-200 dark:border-orange-700',
      };
    case 'tool':
      return {
        bg: 'bg-cyan-50 dark:bg-cyan-900/30',
        text: 'text-cyan-700 dark:text-cyan-300',
        border: 'border-cyan-200 dark:border-cyan-700',
      };
    default:
      return {
        bg: 'bg-gray-50 dark:bg-gray-800',
        text: 'text-gray-700 dark:text-gray-300',
        border: 'border-gray-200 dark:border-gray-700',
      };
  }
}

/**
 * Facet chips component for selecting/filtering by facets
 */
export function FacetChips({
  selectedFacets,
  onFacetToggle,
  onClearFacets,
}: FacetChipsProps) {
  const [facets, setFacets] = useState<FacetCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    async function loadFacets() {
      try {
        setLoading(true);
        const response = await libraryApi.listFacets(undefined, 1);
        setFacets(response.facets);
        setError(null);
      } catch (err) {
        setError('Failed to load facets');
        console.error('Failed to load facets:', err);
      } finally {
        setLoading(false);
      }
    }

    loadFacets();
  }, []);

  if (loading) {
    return (
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-gray-700">
          Topics & Tags
        </label>
        <div className="flex flex-wrap gap-2">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-7 w-20 animate-pulse rounded-full bg-gray-200"
            />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-gray-700">
          Topics & Tags
        </label>
        <p className="text-sm text-red-600">{error}</p>
      </div>
    );
  }

  if (facets.length === 0) {
    return null;
  }

  const displayFacets = expanded ? facets : facets.slice(0, 8);
  const hasMore = facets.length > 8;

  return (
    <div className="mb-4">
      <div className="mb-2 flex items-center justify-between">
        <label className="text-sm font-medium text-gray-700">
          Topics & Tags
        </label>
        {selectedFacets.length > 0 && (
          <button
            type="button"
            onClick={onClearFacets}
            className="text-xs text-indigo-600 hover:text-indigo-500"
          >
            Clear all
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        {displayFacets.map((facet) => {
          const isSelected = selectedFacets.includes(facet.facet_id);
          const colors = getFacetTypeColor(facet.type);

          return (
            <button
              key={facet.facet_id}
              type="button"
              onClick={() => onFacetToggle(facet.facet_id)}
              className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                isSelected
                  ? `${colors.bg} ${colors.text} ${colors.border} ring-2 ring-indigo-500 ring-offset-1`
                  : `${colors.bg} ${colors.text} ${colors.border} hover:ring-1 hover:ring-gray-300`
              }`}
            >
              {facet.name}
              <span className="ml-1.5 text-gray-400">({facet.video_count})</span>
              {isSelected && (
                <XMarkIcon className="ml-1 h-3.5 w-3.5" aria-hidden="true" />
              )}
            </button>
          );
        })}
      </div>
      {hasMore && (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="mt-2 text-xs text-indigo-600 hover:text-indigo-500"
        >
          {expanded ? 'Show less' : `Show ${facets.length - 8} more`}
        </button>
      )}
    </div>
  );
}

export default FacetChips;
