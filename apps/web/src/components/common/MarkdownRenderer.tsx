'use client';

import ReactMarkdown from 'react-markdown';
import type { Components } from 'react-markdown';

/**
 * Shared prose styling classes for markdown content
 * Using Tailwind Typography plugin with consistent theming
 */
export const PROSE_CLASSES = [
  'prose',
  'prose-sm',
  'dark:prose-invert',
  'max-w-none',
  // Headings
  'prose-headings:text-gray-900',
  'dark:prose-headings:text-white',
  'prose-headings:font-semibold',
  'prose-headings:mt-4',
  'prose-headings:mb-2',
  // Paragraphs
  'prose-p:text-gray-700',
  'dark:prose-p:text-gray-300',
  'prose-p:leading-relaxed',
  'prose-p:my-2',
  // Lists
  'prose-li:text-gray-700',
  'dark:prose-li:text-gray-300',
  'prose-li:my-0.5',
  'prose-ul:my-2',
  'prose-ol:my-2',
  // Strong/Bold
  'prose-strong:text-gray-900',
  'dark:prose-strong:text-white',
  'prose-strong:font-semibold',
  // Links
  'prose-a:text-red-600',
  'dark:prose-a:text-red-400',
  'prose-a:no-underline',
  'hover:prose-a:underline',
  // Code
  'prose-code:text-sm',
  'prose-code:bg-gray-100',
  'dark:prose-code:bg-gray-800',
  'prose-code:px-1',
  'prose-code:py-0.5',
  'prose-code:rounded',
].join(' ');

/**
 * Variant-specific prose classes
 */
export const PROSE_VARIANTS = {
  default: PROSE_CLASSES,
  compact: `${PROSE_CLASSES} prose-p:my-1 prose-headings:mt-2 prose-headings:mb-1`,
  large: PROSE_CLASSES.replace('prose-sm', 'prose-base'),
  // Summary variant - clean styling for AI-generated summaries
  summary: [
    'prose',
    'prose-base', // Larger base font
    'dark:prose-invert',
    'max-w-none',
    // Headings - clear section dividers with background
    'prose-headings:text-gray-900',
    'dark:prose-headings:text-white',
    'prose-headings:font-bold',
    'prose-h2:text-sm',
    'prose-h2:uppercase',
    'prose-h2:tracking-wide',
    'prose-h2:mt-8',
    'prose-h2:mb-4',
    'prose-h2:first:mt-0',
    'prose-h2:text-red-600',
    'dark:prose-h2:text-red-400',
    // Paragraphs
    'prose-p:text-gray-700',
    'dark:prose-p:text-gray-300',
    'prose-p:leading-7',
    'prose-p:my-4',
    // Ordered lists - numbered with good spacing
    'prose-ol:my-4',
    'prose-ol:pl-6',
    'prose-ol:space-y-3',
    'prose-li:text-gray-700',
    'dark:prose-li:text-gray-300',
    'prose-li:leading-7',
    'prose-li:my-0',
    // Strong text
    'prose-strong:text-gray-900',
    'dark:prose-strong:text-white',
    'prose-strong:font-semibold',
  ].join(' '),
} as const;

export type ProseVariant = keyof typeof PROSE_VARIANTS;

interface MarkdownRendererProps {
  /** Markdown content to render */
  content: string;
  /** Visual variant for styling */
  variant?: ProseVariant;
  /** Additional CSS classes */
  className?: string;
  /** Custom component overrides for react-markdown */
  components?: Components;
}

/**
 * Shared Markdown renderer component with consistent styling
 * 
 * @example
 * ```tsx
 * <MarkdownRenderer content={summaryText} variant="compact" />
 * ```
 */
export function MarkdownRenderer({
  content,
  variant = 'default',
  className = '',
  components,
}: MarkdownRendererProps) {
  const proseClasses = PROSE_VARIANTS[variant];
  // Add prose-summary class for CSS-based h2 styling
  const variantClass = variant === 'summary' ? 'prose-summary' : '';
  
  return (
    <article className={`${proseClasses} ${variantClass} ${className}`}>
      <ReactMarkdown components={components}>
        {content}
      </ReactMarkdown>
    </article>
  );
}

export default MarkdownRenderer;
