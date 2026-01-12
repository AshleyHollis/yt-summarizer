/**
 * Reusable styling utilities for CopilotKit components.
 *
 * This file centralizes all copilot styling patterns to:
 * 1. Avoid conflicts with CopilotKit's internal styles
 * 2. Ensure consistency across all copilot components
 * 3. Make styling changes easy to maintain
 *
 * All styles use CopilotKit CSS variables for theme compatibility.
 */

/**
 * Base box styling pattern - the standard container style
 * Used for: answer boxes, follow-up containers, video cards containers, etc.
 */
export const copilotBoxStyles = {
  base: "bg-[var(--copilot-kit-secondary-color)] rounded-xl border border-[var(--copilot-kit-separator-color)]",
  hover: "hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150",
  padding: "p-4",
  /** Interactive box with hover effect - use for clickable elements */
  full: "bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150",
  /** Non-interactive box without hover effect - use for display-only containers */
  static: "bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)]",
} as const;

/**
 * Text sizes - standardized across all copilot components
 */
export const copilotTextSizes = {
  /** Standard body text - 15px */
  body: "text-[15px]",
  /** Small text for secondary info - 13px */
  small: "text-[13px]",
  /** Extra small for tertiary info - 11px */
  xs: "text-[11px]",
  /** Section headers */
  header: "text-[15px] font-semibold",
} as const;

/**
 * Text colors using CopilotKit variables
 */
export const copilotColors = {
  /** Primary text color */
  primary: "text-[var(--copilot-kit-secondary-contrast-color)]",
  /** Muted/secondary text */
  muted: "text-[var(--copilot-kit-muted-color)]",
  /** Accent color (red) */
  accent: "text-[var(--copilot-kit-primary-color)]",
  /** Background colors */
  bg: {
    primary: "bg-[var(--copilot-kit-background-color)]",
    secondary: "bg-[var(--copilot-kit-secondary-color)]",
  },
  /** Border colors */
  border: {
    default: "border-[var(--copilot-kit-separator-color)]",
    accent: "border-[var(--copilot-kit-primary-color)]",
  },
} as const;

/**
 * Button styling patterns
 */
export const copilotButtonStyles = {
  /** Icon button - subtle hover */
  icon: "p-1.5 rounded-md hover:bg-[var(--copilot-kit-secondary-color)] text-[var(--copilot-kit-muted-color)] transition-colors",
  /** Icon button with accent color */
  iconAccent: "p-1.5 rounded-md hover:bg-[var(--copilot-kit-secondary-color)] text-[var(--copilot-kit-primary-color)] transition-colors",
  /** Interactive item with hover */
  interactive: "hover:bg-[var(--copilot-kit-secondary-color)]/60 hover:border-[var(--copilot-kit-primary-color)]/50 transition-all duration-150 cursor-pointer",
} as const;

/**
 * Thread dropdown specific styles - YouTube-inspired with red borders on hover
 */
export const copilotThreadStyles = {
  /** Container for thread dropdown */
  container: "border-b border-[var(--copilot-kit-separator-color)] bg-[var(--copilot-kit-secondary-color)]",
  /** Expanded container with extra padding */
  expanded: "pb-2",
  /** Header row */
  header: "flex items-center justify-between px-3 py-2",
  /** Thread button/toggle - red border on hover */
  toggle: "group flex items-center gap-2 flex-1 min-w-0 border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-background-color)] rounded-lg px-2 py-1.5 -mx-2 transition-all duration-150",
  /** Toggle button for collapse/expand */
  toggleButton: "group flex items-center gap-2 flex-1 min-w-0 border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-background-color)] rounded-lg px-3 py-2 transition-all duration-150 text-[13px] text-[var(--copilot-kit-secondary-contrast-color)]",
  /** Thread title text */
  title: "text-[13px] text-[var(--copilot-kit-secondary-contrast-color)] overflow-hidden text-ellipsis whitespace-nowrap",
  /** Thread title when active */
  titleActive: "text-[13px] text-[var(--copilot-kit-primary-color)] font-medium overflow-hidden text-ellipsis whitespace-nowrap",
  /** Thread metadata (date, count) */
  meta: "text-[11px] text-[var(--copilot-kit-muted-color)]",
  /** Thread list container */
  list: "max-h-[200px] overflow-y-auto",
  /** Empty state when no threads */
  emptyState: "flex flex-col items-center justify-center py-6 text-[var(--copilot-kit-muted-color)] text-[13px] gap-2",
  /** Thread list item - red border on hover */
  item: "flex items-center gap-2 px-3 py-2 cursor-pointer transition-all duration-150 group mx-1 my-0.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)]",
  /** Thread item in list */
  threadItem: "flex items-center gap-2 px-3 py-2 cursor-pointer transition-all duration-150 group mx-1 my-0.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-background-color)]",
  /** Active thread item in list */
  threadItemActive: "bg-[var(--copilot-kit-primary-color)]/10 border-[var(--copilot-kit-primary-color)]",
  /** Thread content container */
  threadContent: "flex-1 min-w-0",
  /** Thread title in list */
  threadTitle: "text-[13px] text-[var(--copilot-kit-secondary-contrast-color)] overflow-hidden text-ellipsis whitespace-nowrap",
  /** Thread metadata in list */
  threadMeta: "text-[11px] text-[var(--copilot-kit-muted-color)]",
  /** Active thread item */
  itemActive: "bg-[var(--copilot-kit-primary-color)]/10 border-l-2 border-[var(--copilot-kit-primary-color)] rounded-l-none",
  /** Inactive thread item */
  itemInactive: "hover:bg-[var(--copilot-kit-background-color)] border-l-2 border-transparent",
  /** New chat button - red border on hover */
  newButton: "p-1.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-primary-color)] hover:bg-[var(--copilot-kit-background-color)] text-[var(--copilot-kit-primary-color)] flex-shrink-0 transition-all duration-150",
  /** Delete button for thread items */
  deleteButton: "opacity-0 group-hover:opacity-100 p-1.5 rounded-lg hover:bg-[var(--copilot-kit-primary-color)]/20 text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-primary-color)] transition-all duration-150",
  /** Icon styling with group hover for red color */
  icon: "w-4 h-4 text-[var(--copilot-kit-muted-color)] group-hover:text-[var(--copilot-kit-primary-color)] transition-colors flex-shrink-0",
} as const;

/**
 * Initial/implicit message styles
 */
export const copilotImplicitMessageStyles = {
  /** Container for the implicit message */
  container: "bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150 mb-4",
  /** Message text */
  text: "text-[15px] text-[var(--copilot-kit-secondary-contrast-color)]",
} as const;

/**
 * Simple class name utility
 */
export function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(" ");
}
