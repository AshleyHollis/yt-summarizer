'use client';

/**
 * ToolResultContext - Frontend Tool Result Bridge
 *
 * ## Purpose
 *
 * This context bridges the gap between frontend tool execution (Pattern A) and
 * thread persistence. When a frontend tool executes, its result needs to be
 * saved to the thread, but CopilotKit doesn't automatically include it in
 * the message list that we save.
 *
 * ## How It Works
 *
 * 1. Frontend tool executes via `useCopilotAction` (Pattern A)
 * 2. Tool calls `registerToolResult(toolCallId, toolName, result)`
 * 3. `useThreadPersistence` subscribes to these results
 * 4. When saving messages, pending results are merged in
 *
 * ## Flow Diagram
 *
 * ```
 * useCopilotAction (frontend tool)
 *   ↓
 * registerToolResult()
 *   ↓
 * ToolResultContext stores result
 *   ↓
 * useThreadPersistence.subscribe() notified
 *   ↓
 * saveIfNeeded() includes tool result in saved messages
 * ```
 *
 * ## Why This Is Needed
 *
 * Backend tools (Pattern B) automatically have their results in the message
 * stream from CopilotKit. But frontend tools execute locally and their results
 * aren't automatically in the stream - we need to manually bridge them.
 *
 * ## Note on Backend Tools
 *
 * For backend tools (query_library, etc.), CopilotKit handles the tool result
 * messages automatically. This context is only needed for Pattern A frontend tools.
 *
 * @see useCopilotActions.tsx - Where frontend tools call registerToolResult
 * @see useThreadPersistence.ts - Where results are consumed during save
 */

import { createContext, useContext, useCallback, useRef, ReactNode, useMemo } from 'react';

export interface PendingToolResult {
  toolCallId: string;
  toolName: string;
  result: unknown;
  timestamp: number;
}

interface ToolResultContextValue {
  /**
   * Register a tool result that should be persisted.
   * Called by useCopilotActions when a frontend tool completes.
   */
  registerToolResult: (toolCallId: string, toolName: string, result: unknown) => void;

  /**
   * Get all pending tool results and clear them.
   * Called by useThreadPersistence when saving messages.
   */
  consumePendingResults: () => PendingToolResult[];

  /**
   * Subscribe to new tool results for immediate persistence.
   */
  subscribe: (callback: (result: PendingToolResult) => void) => () => void;
}

const ToolResultContext = createContext<ToolResultContextValue | null>(null);

export function ToolResultProvider({ children }: { children: ReactNode }) {
  const pendingResultsRef = useRef<PendingToolResult[]>([]);
  const subscribersRef = useRef<Set<(result: PendingToolResult) => void>>(new Set());

  const registerToolResult = useCallback(
    (toolCallId: string, toolName: string, result: unknown) => {
      const toolResult: PendingToolResult = {
        toolCallId,
        toolName,
        result,
        timestamp: Date.now(),
      };

      // Add to pending results
      pendingResultsRef.current.push(toolResult);

      // Notify subscribers immediately
      subscribersRef.current.forEach((callback) => callback(toolResult));
    },
    []
  );

  const consumePendingResults = useCallback(() => {
    const results = [...pendingResultsRef.current];
    pendingResultsRef.current = [];
    return results;
  }, []);

  const subscribe = useCallback((callback: (result: PendingToolResult) => void) => {
    subscribersRef.current.add(callback);
    return () => {
      subscribersRef.current.delete(callback);
    };
  }, []);

  const value = useMemo(
    () => ({
      registerToolResult,
      consumePendingResults,
      subscribe,
    }),
    [registerToolResult, consumePendingResults, subscribe]
  );

  return <ToolResultContext.Provider value={value}>{children}</ToolResultContext.Provider>;
}

export function useToolResults() {
  const context = useContext(ToolResultContext);
  if (!context) {
    throw new Error('useToolResults must be used within a ToolResultProvider');
  }
  return context;
}

/**
 * Optional hook that returns null if not in a ToolResultProvider.
 * Useful for hooks that may be used outside the provider.
 */
export function useToolResultsOptional() {
  return useContext(ToolResultContext);
}
