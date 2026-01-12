/**
 * Date formatting utilities
 *
 * Consolidates date formatting across the application to ensure consistency.
 */

/**
 * Format date string to short localized date (e.g., "Jan 7, 2026")
 */
export function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Format date string to long localized date (e.g., "January 7, 2026")
 */
export function formatDateLong(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/**
 * Format date string to localized date with time (e.g., "Jan 7, 2026, 10:30 AM")
 */
export function formatDateTime(dateString: string | null): string {
  if (!dateString) return '-';
  const date = new Date(dateString);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format ISO datetime string to just time (for compact display)
 */
export function formatTime(isoString: string | null): string {
  if (!isoString) return '-';
  const date = new Date(isoString);
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Format ISO datetime string to short time (hour:minute only, no seconds)
 * Handles both UTC and local time strings.
 */
export function formatTimeShort(isoString: string): string {
  const dateStr = isoString.endsWith('Z') ? isoString : isoString + 'Z';
  const date = new Date(dateStr);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Format current date to simple locale date string (e.g., "1/7/2026")
 * Useful for auto-generated names like batch names.
 */
export function formatDateShort(date: Date = new Date()): string {
  return date.toLocaleDateString();
}

/**
 * Format timestamp to relative time (e.g., "Today", "Yesterday", "3d ago")
 */
export function formatRelativeDate(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}
