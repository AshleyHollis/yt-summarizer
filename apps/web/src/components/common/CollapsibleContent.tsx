'use client';

import { useState, useRef, useEffect, type ReactNode } from 'react';
import { ChevronDownIcon, ChevronUpIcon } from '@heroicons/react/24/outline';

interface CollapsibleContentProps {
  /** Content to display */
  children: ReactNode;
  /** Maximum height in pixels when collapsed (default: 200) */
  collapsedHeight?: number;
  /** Whether to start expanded (default: false) */
  defaultExpanded?: boolean;
  /** Label for expand button (default: "Show more") */
  expandLabel?: string;
  /** Label for collapse button (default: "Show less") */
  collapseLabel?: string;
  /** Additional CSS classes for the container */
  className?: string;
  /** Whether to show gradient fade when collapsed (default: true) */
  showGradient?: boolean;
  /** Gradient color class (default: "from-transparent to-white dark:to-gray-800") */
  gradientClass?: string;
}

/**
 * Collapsible content wrapper with smooth height transitions
 *
 * Automatically detects if content exceeds the collapsed height
 * and shows expand/collapse controls when needed.
 *
 * @example
 * ```tsx
 * <CollapsibleContent collapsedHeight={150}>
 *   <MarkdownRenderer content={longText} />
 * </CollapsibleContent>
 * ```
 */
export function CollapsibleContent({
  children,
  collapsedHeight = 200,
  defaultExpanded = false,
  expandLabel = 'Show more',
  collapseLabel = 'Show less',
  className = '',
  showGradient = true,
  gradientClass = 'from-transparent to-white dark:to-gray-800',
}: CollapsibleContentProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const [needsCollapse, setNeedsCollapse] = useState(false);
  const [contentHeight, setContentHeight] = useState<number | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  // Measure content height to determine if collapse is needed
  useEffect(() => {
    const measureContent = () => {
      if (contentRef.current) {
        const height = contentRef.current.scrollHeight;
        setContentHeight(height);
        setNeedsCollapse(height > collapsedHeight);
      }
    };

    measureContent();

    // Re-measure on window resize
    window.addEventListener('resize', measureContent);
    return () => window.removeEventListener('resize', measureContent);
  }, [children, collapsedHeight]);

  // Calculate the max-height for transitions
  const maxHeight = isExpanded || !needsCollapse ? (contentHeight ?? 'none') : collapsedHeight;

  return (
    <div className={`relative ${className}`}>
      {/* Content container with transition */}
      <div
        ref={contentRef}
        className="transition-[max-height] duration-300 ease-in-out overflow-hidden"
        style={{
          maxHeight: typeof maxHeight === 'number' ? `${maxHeight}px` : maxHeight,
        }}
      >
        {children}
      </div>

      {/* Gradient overlay when collapsed */}
      {needsCollapse && !isExpanded && showGradient && (
        <div
          className={`absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t ${gradientClass} pointer-events-none`}
        />
      )}

      {/* Expand/Collapse button */}
      {needsCollapse && (
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full flex items-center justify-center gap-1.5 py-2 mt-1 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
          aria-expanded={isExpanded}
        >
          {isExpanded ? (
            <>
              {collapseLabel}
              <ChevronUpIcon className="h-4 w-4" />
            </>
          ) : (
            <>
              {expandLabel}
              <ChevronDownIcon className="h-4 w-4" />
            </>
          )}
        </button>
      )}
    </div>
  );
}

export default CollapsibleContent;
