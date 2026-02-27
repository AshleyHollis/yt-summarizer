/**
 * useThreadPersistence Hook
 *
 * React hook for managing chat thread persistence with clean, deterministic behavior.
 * This is the core state management for thread CRUD operations.
 *
 * ## ARCHITECTURE
 *
 * This hook manages:
 * - Thread list (fetching, polling for updates)
 * - Active thread selection and loading
 * - Auto-saving messages with debounce
 * - Thread creation (with state machine to prevent duplicates)
 *
 * ## KEY DESIGN DECISIONS
 *
 * 1. **No URL management** - The component (ThreadedCopilotSidebar) handles URL.
 *    This hook just calls onThreadIdChange() when thread changes.
 *
 * 2. **Refs for non-render values** - saveStateRef, loadedThreadRef, etc.
 *    Avoids unnecessary re-renders during save operations.
 *
 * 3. **State machine for creation** - threadCreationTracker in threadPersistence.ts
 *    Prevents duplicate thread creation when messages stream in quickly.
 *
 * 4. **Hash-based change detection** - computeMessageHash()
 *    Only saves when content actually changes, not on every render.
 *
 * ## THREAD SWITCHING FLOW
 *
 * ```
 * selectThread(id)
 *   ↓
 * setState({ activeThreadId: id })
 *   ↓
 * onThreadIdChange(id)  ← Component updates URL
 *   ↓
 * useEffect detects activeThreadId change
 *   ↓
 * fetchThread(id)
 *   ↓
 * setMessages(prepareMessagesForDisplay(messages))
 *   ↓
 * CopilotKit re-renders with rich UI
 * ```
 *
 * ## MESSAGE LOADING (Critical for Rich UI)
 *
 * When loading messages, we MUST call prepareMessagesForDisplay():
 *
 * ```typescript
 * // ✅ CORRECT - toolCalls reconstructed, rich UI works
 * setMessages(prepareMessagesForDisplay(result.messages));
 *
 * // ❌ WRONG - no toolCalls, shows blank or plain text
 * setMessages(result.messages);
 * ```
 *
 * ## MESSAGE SAVING
 *
 * When saving messages, we MUST use copilotToThreadMessages():
 *
 * ```typescript
 * // ✅ CORRECT - preserves tool call information
 * await saveMessages(threadId, copilotToThreadMessages(messages));
 *
 * // ❌ WRONG - loses CopilotKit's internal message format
 * await saveMessages(threadId, messages);
 * ```
 *
 * @see ThreadedCopilotSidebar.tsx - Uses this hook
 * @see threadPersistence.ts - API layer and message transformation
 */

'use client';

import { useCallback, useRef, useEffect, useState, useMemo } from 'react';
import {
  ChatThread,
  ThreadMessage,
  threadCreationTracker,
  fetchThreads,
  fetchThread,
  createThread,
  saveMessages,
  deleteThread as deleteThreadApi,
  generateTitle,
  computeMessageHash,
  updateThreadSettings,
  QueryScope,
  AISettings,
} from '@/services/threadPersistence';
import { useToolResultsOptional, PendingToolResult } from '@/contexts/ToolResultContext';

// ============================================================================
// Configuration
// ============================================================================

const SAVE_DEBOUNCE_MS = 1000; // Debounce to allow tool results to be added by CopilotKit
const THREAD_POLL_INTERVAL_MS = 30000; // Poll for updates from other sessions

// ============================================================================
// Hook State Types
// ============================================================================

interface ThreadState {
  threads: ChatThread[];
  activeThreadId: string | null;
  isLoading: boolean;
  error: string | null;
}

interface SaveState {
  lastHash: string;
  lastCount: number;
  pendingSave: ReturnType<typeof setTimeout> | null;
}

// ============================================================================
// Main Hook
// ============================================================================

export interface UseThreadPersistenceOptions {
  /** Initial thread ID from URL or other source */
  initialThreadId?: string | null;
  /** Get current messages from CopilotKit */
  getMessages: () => ThreadMessage[];
  /** Set messages in CopilotKit */
  setMessages: (messages: ThreadMessage[]) => void;
  /** Callback when thread ID changes (for URL sync) */
  onThreadIdChange?: (threadId: string | null) => void;
  /** Get current scope for persisting with thread */
  getScope?: () => QueryScope;
  /** Set scope when loading thread */
  setScope?: (scope: QueryScope) => void;
  /** Get current AI settings for persisting with thread */
  getAISettings?: () => AISettings;
  /** Set AI settings when loading thread */
  setAISettings?: (settings: Partial<AISettings>) => void;
}

export interface UseThreadPersistenceResult {
  // State
  threads: ChatThread[];
  activeThreadId: string | null;
  isLoading: boolean;
  error: string | null;
  /** True while thread settings are being restored (don't save during this time) */
  isRestoringSettings: boolean;

  // Thread operations
  startNewChat: () => void;
  selectThread: (threadId: string) => Promise<void>;
  deleteThread: (threadId: string) => Promise<void>;

  // Sync external thread ID (from URL)
  syncThreadIdFromUrl: (threadId: string | null) => void;

  // Save trigger (call when messages change)
  saveIfNeeded: () => void;

  // Force reload of a specific thread
  reloadThread: (threadId: string) => Promise<void>;

  // Update thread settings mid-conversation
  saveSettingsToThread: () => Promise<void>;
}

export function useThreadPersistence({
  initialThreadId,
  getMessages,
  setMessages,
  onThreadIdChange,
  getScope,
  setScope,
  getAISettings,
  setAISettings,
}: UseThreadPersistenceOptions): UseThreadPersistenceResult {
  // Get tool result context for frontend tool results
  const toolResultsContext = useToolResultsOptional();

  // Core thread state
  const [state, setState] = useState<ThreadState>({
    threads: [],
    activeThreadId: initialThreadId || null,
    isLoading: true,
    error: null,
  });

  // Save state (refs to avoid re-renders)
  const saveStateRef = useRef<SaveState>({
    lastHash: '',
    lastCount: 0,
    pendingSave: null,
  });

  // Store pending tool results that need to be added to messages
  const pendingToolResultsRef = useRef<PendingToolResult[]>([]);

  // Track which threads have been auto-titled
  const titledThreadsRef = useRef<Set<string>>(new Set());

  // Track if we've loaded the current thread's messages
  const loadedThreadRef = useRef<string | null>(null);

  // Track if we're in the middle of restoring settings from a loaded thread
  // Initialize to true if we have an initial thread ID (prevents save before load)
  const [isRestoringSettings, setIsRestoringSettings] = useState(!!initialThreadId);

  // Subscribe to tool results from the context
  useEffect(() => {
    if (!toolResultsContext) return;

    const unsubscribe = toolResultsContext.subscribe((result) => {
      // Store the result to be included in the next save
      pendingToolResultsRef.current.push(result);
    });

    return unsubscribe;
  }, [toolResultsContext]);

  // ============================================================================
  // Thread List Operations
  // ============================================================================

  /**
   * Load initial thread list on mount
   */
  useEffect(() => {
    let mounted = true;

    const loadInitialThreads = async () => {
      try {
        const threads = await fetchThreads();
        if (!mounted) return;

        // Validate that the initial thread exists
        const validatedId =
          initialThreadId && threads.some((t) => t.id === initialThreadId) ? initialThreadId : null;

        setState((prev) => ({
          ...prev,
          threads,
          activeThreadId: validatedId,
          isLoading: false,
        }));

        // Notify if initial thread was invalid
        if (initialThreadId && !validatedId) {
          onThreadIdChange?.(null);
        }
      } catch {
        if (!mounted) return;
        setState((prev) => ({
          ...prev,
          error: 'Failed to load threads',
          isLoading: false,
        }));
      }
    };

    loadInitialThreads();

    return () => { mounted = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Only run on mount - don't depend on initialThreadId to avoid re-fetching

  /**
   * Poll for thread list updates (catches cross-tab/browser changes)
   */
  useEffect(() => {
    if (typeof window === 'undefined') return;

    let intervalId: ReturnType<typeof setInterval> | null = null;

    const poll = async () => {
      if (document.hidden) return; // Skip when tab not visible

      try {
        const threads = await fetchThreads();
        setState((prev) => {
          // Only update if IDs changed
          const prevIds = new Set(prev.threads.map((t) => t.id));
          const newIds = new Set(threads.map((t) => t.id));

          const changed =
            prevIds.size !== newIds.size ||
            threads.some((t) => !prevIds.has(t.id)) ||
            prev.threads.some((t) => !newIds.has(t.id));

          return changed ? { ...prev, threads } : prev;
        });
      } catch {
        // Silently ignore polling errors
      }
    };

    const start = () => {
      intervalId = setInterval(poll, THREAD_POLL_INTERVAL_MS);
    };
    const stop = () => {
      if (intervalId) clearInterval(intervalId);
    };

    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        poll();
        start();
      }
    };

    if (!document.hidden) start();
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  // ============================================================================
  // Thread Selection & Loading
  // ============================================================================

  /**
   * Load messages when active thread changes
   */
  useEffect(() => {
    const { activeThreadId, isLoading } = state;

    // Don't load while still loading thread list
    if (isLoading) return;

    // Already loaded this thread
    if (loadedThreadRef.current === activeThreadId) return;

    // No thread selected - clear messages
    if (!activeThreadId) {
      loadedThreadRef.current = null;
      setMessages([]);
      saveStateRef.current = { lastHash: '', lastCount: 0, pendingSave: null };
      return;
    }

    // Load thread messages
    loadedThreadRef.current = activeThreadId;

    // Mark that we're restoring settings (prevents immediate save overwrite)
    setIsRestoringSettings(true);

    fetchThread(activeThreadId)
      .then((result) => {
        if (!result || loadedThreadRef.current !== activeThreadId) {
          setIsRestoringSettings(false);
          return;
        }

        setMessages(result.messages);
        saveStateRef.current.lastHash = computeMessageHash(result.messages);
        saveStateRef.current.lastCount = result.messages.length;

        // Restore scope and AI settings from the thread
        if (result.thread.scope && setScope) {
          setScope(result.thread.scope);
        }
        if (result.thread.aiSettings && setAISettings) {
          setAISettings(result.thread.aiSettings);
        }

        // Allow a brief moment for state to propagate, then allow saving again
        setTimeout(() => setIsRestoringSettings(false), 100);
      })
      .catch((err) => {
        console.error('Failed to load thread:', err);
        setMessages([]);
        setIsRestoringSettings(false);
        return;
      }

      setMessages(result.messages);
      saveStateRef.current.lastHash = computeMessageHash(result.messages);
      saveStateRef.current.lastCount = result.messages.length;

      // Restore scope and AI settings from the thread
      if (result.thread.scope && setScope) {
        setScope(result.thread.scope);
      }
      if (result.thread.aiSettings && setAISettings) {
        setAISettings(result.thread.aiSettings);
      }

      // Allow a brief moment for state to propagate, then allow saving again
      setTimeout(() => setIsRestoringSettings(false), 100);
    }).catch(err => {
      console.error("Failed to load thread:", err);
      setMessages([]);
      setIsRestoringSettings(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.activeThreadId, state.isLoading, setMessages, setScope, setAISettings]);

  /**
   * Sync thread ID from external source (URL)
   */
  const syncThreadIdFromUrl = useCallback((threadId: string | null) => {
    setState((prev) => {
      if (prev.activeThreadId === threadId) return prev;

      // Validate thread exists
      if (threadId && !prev.threads.some((t) => t.id === threadId)) {
        return prev; // Invalid thread ID, don't update
      }

      // Clear loaded ref to trigger reload
      loadedThreadRef.current = null;

      return { ...prev, activeThreadId: threadId };
    });
  }, []);

  /**
   * Force reload a thread
   */
  const reloadThread = useCallback(
    async (threadId: string) => {
      loadedThreadRef.current = null; // Force reload

      try {
        const result = await fetchThread(threadId);
        if (result) {
          setMessages(result.messages);
          saveStateRef.current.lastHash = computeMessageHash(result.messages);
          saveStateRef.current.lastCount = result.messages.length;
          loadedThreadRef.current = threadId;
        }
      } catch (err) {
        console.error('Failed to reload thread:', err);
      }
    },
    [setMessages]
  );

  /**
   * Select a thread (load its messages)
   */
  const selectThread = useCallback(
    async (threadId: string) => {
      // Clear loaded ref to trigger reload
      loadedThreadRef.current = null;
      saveStateRef.current = { lastHash: '', lastCount: 0, pendingSave: null };

      setState((prev) => ({ ...prev, activeThreadId: threadId }));
      onThreadIdChange?.(threadId);
    },
    [onThreadIdChange]
  );

  /**
   * Start a fresh chat (no thread yet)
   */
  const startNewChat = useCallback(() => {
    // Reset creation tracker for new chat
    threadCreationTracker.reset();

    // Clear state
    loadedThreadRef.current = null;
    saveStateRef.current = { lastHash: '', lastCount: 0, pendingSave: null };
    titledThreadsRef.current.clear();

    setState((prev) => ({ ...prev, activeThreadId: null }));

    // Clear messages and notify
    setMessages([]);
    onThreadIdChange?.(null);
  }, [setMessages, onThreadIdChange]);

  /**
   * Delete a thread
   */
  const deleteThreadHandler = useCallback(
    async (threadId: string) => {
      await deleteThreadApi(threadId);

      setState((prev) => {
        const remaining = prev.threads.filter((t) => t.id !== threadId);
        const wasActive = prev.activeThreadId === threadId;
        const newActiveId = wasActive ? remaining[0]?.id || null : prev.activeThreadId;

        if (wasActive) {
          loadedThreadRef.current = null;
          onThreadIdChange?.(newActiveId);
        }

        return { ...prev, threads: remaining, activeThreadId: newActiveId };
      });
    },
    [onThreadIdChange]
  );

  // ============================================================================
  // Message Saving
  // ============================================================================

  /**
   * Convert pending tool results to ThreadMessages
   */
  const getToolResultMessages = useCallback((): ThreadMessage[] => {
    const pendingResults = [...pendingToolResultsRef.current];
    pendingToolResultsRef.current = [];

    return pendingResults.map((result) => ({
      id: `tool-result-${result.toolCallId}`,
      role: 'tool' as const,
      content: typeof result.result === 'string' ? result.result : JSON.stringify(result.result),
      toolCallId: result.toolCallId,
    }));
  }, []);

  /**
   * Save messages if they've changed.
   * Debounces rapid updates but is otherwise deterministic.
   */
  const saveIfNeeded = useCallback(() => {
    const messages = getMessages();
    const { activeThreadId: currentActiveThreadId } = state;

    // Add any pending tool results to the messages
    const toolResultMessages = getToolResultMessages();
    const allMessages = [...messages, ...toolResultMessages];

    // Nothing to save
    if (!allMessages || allMessages.length === 0) return;

    // Check if messages actually changed
    const { lastHash, lastCount, pendingSave } = saveStateRef.current;
    const currentHash = computeMessageHash(allMessages);

    const hasNewMessages = allMessages.length > lastCount;
    const hashChanged = currentHash !== lastHash && lastHash !== '';
    const hasToolResults = toolResultMessages.length > 0;

    if (!hasNewMessages && !hashChanged && !hasToolResults) return;

    // Clear any pending save
    if (pendingSave) clearTimeout(pendingSave);

    // Debounce the actual save for UX (avoid API spam during streaming)
    saveStateRef.current.pendingSave = setTimeout(async () => {
      const currentMessages = getMessages();
      // Re-get tool results in case more arrived during debounce
      const currentToolResults = getToolResultMessages();
      const messagesToSave = [...currentMessages, ...currentToolResults];

      if (!messagesToSave || messagesToSave.length === 0) return;

      // Get first user message for title
      const firstUserMessage = messagesToSave.find((m) => m.role === 'user');
      if (!firstUserMessage) return;

      const content =
        typeof firstUserMessage.content === 'string'
          ? firstUserMessage.content
          : JSON.stringify(firstUserMessage.content);

      // Update save state
      saveStateRef.current.lastHash = computeMessageHash(messagesToSave);
      saveStateRef.current.lastCount = messagesToSave.length;

      if (currentActiveThreadId) {
        // Save to existing thread
        const needsTitle = !titledThreadsRef.current.has(currentActiveThreadId);
        const title = needsTitle ? generateTitle(content) : undefined;

        if (needsTitle) titledThreadsRef.current.add(currentActiveThreadId);

        try {
          await saveMessages(currentActiveThreadId, messagesToSave, title);

          // Update thread in list
          setState((prev) => ({
            ...prev,
            threads: prev.threads.map((t) =>
              t.id === currentActiveThreadId
                ? {
                    ...t,
                    messageCount: messagesToSave.length,
                    updatedAt: Date.now(),
                    title: title || t.title,
                  }
                : t
            ),
          }));
        } catch (err) {
          console.error('Failed to save messages:', err);
        }
      } else {
        // Create new thread atomically
        const title = generateTitle(content);

        // Get current scope and AI settings to save with thread
        const currentScope = getScope?.() || null;
        const currentAISettings = getAISettings?.() || null;

        try {
          const newThread = await threadCreationTracker.startCreation(() =>
            createThread(messagesToSave, title, currentScope, currentAISettings)
          );

          if (!newThread) return;

          // Update state
          titledThreadsRef.current.add(newThread.id);
          loadedThreadRef.current = newThread.id;

          setState((prev) => ({
            ...prev,
            threads: [newThread, ...prev.threads],
            activeThreadId: newThread.id,
          }));

          onThreadIdChange?.(newThread.id);
        } catch (err) {
          console.error('Failed to create thread:', err);
        }
      }
    }, SAVE_DEBOUNCE_MS);
  }, [getMessages, state, onThreadIdChange, getScope, getAISettings, getToolResultMessages]);

  /**
   * Save current scope and AI settings to the active thread.
   * Call this when settings change mid-conversation.
   */
  const saveSettingsToThread = useCallback(async () => {
    const { activeThreadId: currentActiveThreadId } = state;

    if (!currentActiveThreadId) {
      // No active thread yet - settings will be saved when thread is created
      return;
    }

    const currentScope = getScope?.() || null;
    const currentAISettings = getAISettings?.() || null;

    try {
      await updateThreadSettings(currentActiveThreadId, currentScope, currentAISettings);
    } catch (err) {
      console.error('Failed to save thread settings:', err);
    }
  }, [state, getScope, getAISettings]);

  // ============================================================================
  // Return Value
  // ============================================================================

  return useMemo(
    () => ({
      threads: state.threads,
      activeThreadId: state.activeThreadId,
      isLoading: state.isLoading,
      error: state.error,
      isRestoringSettings,
      startNewChat,
      selectThread,
      deleteThread: deleteThreadHandler,
      syncThreadIdFromUrl,
      saveIfNeeded,
      reloadThread,
      saveSettingsToThread,
    }),
    [
      state,
      isRestoringSettings,
      startNewChat,
      selectThread,
      deleteThreadHandler,
      syncThreadIdFromUrl,
      saveIfNeeded,
      reloadThread,
      saveSettingsToThread,
    ]
  );
}
