"use client";

/**
 * ThreadedCopilotSidebar Component (Refactored)
 *
 * Uses CopilotKit's Custom Sub-Components pattern for proper customization.
 * Instead of fighting CSS with position:absolute overrides, we:
 * - Pass a custom Header component with our scope indicator built-in
 * - Let CopilotKit manage its own internal layout
 *
 * ## Architecture Overview
 *
 * We compose the sidebar as:
 * ```
 * ┌─────────────────────────────────┐
 * │ CustomHeader (our component)    │ ← Thread selector + scope indicator
 * │   ├── Thread dropdown           │
 * │   └── ScopeIndicator            │
 * ├─────────────────────────────────┤
 * │ CopilotKit Messages Area        │ ← CopilotKit managed
 * ├─────────────────────────────────┤
 * │ CopilotKit Input Area           │ ← CopilotKit managed
 * └─────────────────────────────────┘
 * ```
 *
 * @see https://docs.copilotkit.ai/custom-look-and-feel/bring-your-own-components
 */

import { CopilotSidebar as CKSidebar, CopilotKitCSSProperties } from "@copilotkit/react-ui";
import { useCopilotChatInternal, useCopilotChat } from "@copilotkit/react-core";
import { useCopilotActions } from "@/hooks/useCopilotActions";
import { useTheme } from "next-themes";
import { useEffect, useState, useCallback, useRef, useMemo } from "react";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import { MessageCircle, X } from "lucide-react";
import { useThreadPersistence } from "@/hooks/useThreadPersistence";
import { prepareMessagesForDisplay, copilotToThreadMessages } from "@/services/threadPersistence";
import { CustomHeader } from "./subcomponents/CustomHeader";
import { useScope, useAISettings } from "@/app/providers";
import styles from "./ThreadedCopilotSidebar.module.css";

// ============================================================================
// Constants
// ============================================================================

const SIDEBAR_SIZE_KEY = "copilot-sidebar-size";
const THREADS_COLLAPSED_KEY = "copilot-threads-collapsed";
const MOBILE_BREAKPOINT = 768;

type SizeMode = "compact" | "default" | "half" | "full";

const SIZE_MODES: SizeMode[] = ["compact", "default", "half", "full"];

const SIZE_CONFIG: Record<SizeMode, { width: string; minPx: number }> = {
  compact: { width: "20vw", minPx: 320 },
  default: { width: "30vw", minPx: 380 },
  half: { width: "50vw", minPx: 400 },
  full: { width: "100vw", minPx: 0 },
};

// Theme colors
const THEME_DARK: CopilotKitCSSProperties = {
  "--copilot-kit-primary-color": "#ff0000",
  "--copilot-kit-contrast-color": "#ffffff",
  "--copilot-kit-background-color": "#0f0f0f",
  "--copilot-kit-secondary-color": "#212121",
  "--copilot-kit-secondary-contrast-color": "#f1f1f1",
  "--copilot-kit-separator-color": "#3f3f3f",
  "--copilot-kit-muted-color": "#aaaaaa",
};

const THEME_LIGHT: CopilotKitCSSProperties = {
  "--copilot-kit-primary-color": "#cc0000",
  "--copilot-kit-contrast-color": "#ffffff",
  "--copilot-kit-background-color": "#ffffff",
  "--copilot-kit-secondary-color": "#f2f2f2",
  "--copilot-kit-secondary-contrast-color": "#0f0f0f",
  "--copilot-kit-separator-color": "#e5e5e5",
  "--copilot-kit-muted-color": "#606060",
};

// ============================================================================
// Utilities
// ============================================================================

function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(" ");
}

// ============================================================================
// Component
// ============================================================================

interface ThreadedCopilotSidebarProps {
  defaultOpen?: boolean;
}

export function ThreadedCopilotSidebar({ defaultOpen = false }: ThreadedCopilotSidebarProps) {
  useCopilotActions();

  const { resolvedTheme } = useTheme();
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Scope and AI Settings from providers
  const { scope, setScope } = useScope();
  const { settings: aiSettings, updateSettings: setAISettings } = useAISettings();

  // Memoized getters for scope and AI settings (stable references)
  const getScope = useCallback(() => scope, [scope]);
  const getAISettings = useCallback(() => aiSettings, [aiSettings]);

  // UI State
  const [mounted, setMounted] = useState(false);
  const [sizeMode, setSizeMode] = useState<SizeMode>("default");
  const [threadsCollapsed, setThreadsCollapsed] = useState(true);
  const [isResizing, setIsResizing] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [threadNotFoundMessage, setThreadNotFoundMessage] = useState<string | null>(null);

  // URL-based state
  const isOpen = searchParams.get("chat") === "open" || defaultOpen;
  const urlThreadId = searchParams.get("thread");

  // CopilotKit hooks
  const { agent, messages: internalMessages } = useCopilotChatInternal();
  const { reset: resetCopilotChat } = useCopilotChat();

  // Thread persistence
  const {
    threads,
    activeThreadId,
    isLoading: threadsLoading,
    isRestoringSettings,
    startNewChat,
    selectThread,
    deleteThread: handleDeleteThread,
    syncThreadIdFromUrl,
    saveIfNeeded,
    saveSettingsToThread,
  } = useThreadPersistence({
    initialThreadId: urlThreadId,
    getMessages: () => copilotToThreadMessages(internalMessages || []),
    setMessages: (messages) => {
      if (agent?.setMessages) {
        // Type assertion needed due to mismatch between ThreadMessage and CopilotKit's Message types
        // This works correctly at runtime - the prepareMessagesForDisplay function handles the conversion
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        agent.setMessages(prepareMessagesForDisplay(messages as any) as any);
      }
    },
    onThreadIdChange: (threadId) => {
      const params = new URLSearchParams(searchParams.toString());
      if (threadId) {
        params.set("thread", threadId);
      } else {
        params.delete("thread");
      }
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    // Scope and AI settings persistence
    getScope,
    setScope,
    getAISettings,
    setAISettings,
  });

  // Save settings to thread when scope or AI settings change mid-conversation
  // Skip during restoration to avoid overwriting loaded settings
  useEffect(() => {
    if (activeThreadId && !isRestoringSettings) {
      saveSettingsToThread();
    }
  }, [scope, aiSettings, activeThreadId, isRestoringSettings, saveSettingsToThread]);

  const isDeletingThreadRef = useRef(false);

  // Memoized theme
  const copilotStyles = useMemo(() => {
    const isDark = mounted && resolvedTheme === "dark";
    return isDark ? THEME_DARK : THEME_LIGHT;
  }, [mounted, resolvedTheme]);

  // ============================================================================
  // Effects
  // ============================================================================

  useEffect(() => {
    setMounted(true);

    const savedSize = localStorage.getItem(SIDEBAR_SIZE_KEY) as SizeMode | null;
    if (savedSize && SIZE_MODES.includes(savedSize)) {
      setSizeMode(savedSize);
    }

    const savedThreadsCollapsed = localStorage.getItem(THREADS_COLLAPSED_KEY);
    if (savedThreadsCollapsed !== null) {
      setThreadsCollapsed(savedThreadsCollapsed === "true");
    }

    const checkMobile = () => setIsMobile(window.innerWidth < MOBILE_BREAKPOINT);
    checkMobile();
    window.addEventListener("resize", checkMobile);
    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  // Sync thread ID from URL
  useEffect(() => {
    if (!mounted || threadsLoading) return;

    if (urlThreadId && threads.some((t) => t.id === urlThreadId)) {
      syncThreadIdFromUrl(urlThreadId);
    } else if (urlThreadId && !threads.some((t) => t.id === urlThreadId) && threads.length > 0) {
      if (isDeletingThreadRef.current) {
        isDeletingThreadRef.current = false;
        return;
      }
      setThreadNotFoundMessage("The requested chat thread was not found.");
      setTimeout(() => setThreadNotFoundMessage(null), 5000);
      const params = new URLSearchParams(searchParams.toString());
      params.delete("thread");
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    } else if (!urlThreadId) {
      syncThreadIdFromUrl(null);
    }
  }, [mounted, threadsLoading, urlThreadId, threads, syncThreadIdFromUrl, pathname, router, searchParams]);

  // Save messages when they change
  useEffect(() => {
    if (!mounted || !internalMessages || internalMessages.length === 0) return;
    saveIfNeeded();
  }, [mounted, internalMessages, saveIfNeeded]);

  // Add thread ID to URL when chat opens
  useEffect(() => {
    if (!mounted || threadsLoading || !isOpen) return;

    if (activeThreadId && !urlThreadId) {
      const params = new URLSearchParams(searchParams.toString());
      params.set("thread", activeThreadId);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    }
  }, [mounted, threadsLoading, isOpen, activeThreadId, urlThreadId, pathname, router, searchParams]);

  // Resize drag handlers
  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e: MouseEvent) => {
      const widthPercent = ((window.innerWidth - e.clientX) / window.innerWidth) * 100;

      let newMode: SizeMode;
      if (widthPercent >= 75) newMode = "full";
      else if (widthPercent >= 40) newMode = "half";
      else if (widthPercent >= 25) newMode = "default";
      else newMode = "compact";

      setSizeMode(newMode);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      localStorage.setItem(SIDEBAR_SIZE_KEY, sizeMode);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing, sizeMode]);

  // ============================================================================
  // Handlers
  // ============================================================================

  const handleSetOpen = useCallback(
    (open: boolean) => {
      const params = new URLSearchParams(searchParams.toString());
      params.set("chat", open ? "open" : "closed");
      if (open && activeThreadId) {
        params.set("thread", activeThreadId);
      }
      const newUrl = `${pathname}?${params.toString()}`;
      router.push(newUrl, { scroll: false });
    },
    [pathname, router, searchParams, activeThreadId]
  );

  const handleStartNewChat = useCallback(() => {
    resetCopilotChat();
    startNewChat();
  }, [resetCopilotChat, startNewChat]);

  const handleSelectThread = useCallback(
    (threadId: string) => {
      resetCopilotChat();
      selectThread(threadId);
    },
    [resetCopilotChat, selectThread]
  );

  const handleDeleteThreadWithUrl = useCallback(
    (threadId: string) => {
      isDeletingThreadRef.current = true;
      handleDeleteThread(threadId);
    },
    [handleDeleteThread]
  );

  const handleToggleThreadsCollapsed = useCallback(() => {
    setThreadsCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem(THREADS_COLLAPSED_KEY, String(next));
      return next;
    });
  }, []);

  const handleCycleSize = useCallback(() => {
    const currentIndex = SIZE_MODES.indexOf(sizeMode);
    const nextIndex = (currentIndex + 1) % SIZE_MODES.length;
    const nextMode = SIZE_MODES[nextIndex];
    setSizeMode(nextMode);
    localStorage.setItem(SIDEBAR_SIZE_KEY, nextMode);
  }, [sizeMode]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  // ============================================================================
  // Computed Values
  // ============================================================================

  const displayThreadId = urlThreadId || activeThreadId;
  const activeThreadTitle = threads.find((t) => t.id === displayThreadId)?.title || "New Chat";
  const currentSize = SIZE_CONFIG[sizeMode];
  const chatWidth = isMobile ? "100%" : `max(${currentSize.minPx}px, ${currentSize.width})`;

  // ============================================================================
  // Custom Header Component
  // ============================================================================

  /**
   * Create the Header component to pass to CopilotSidebar.
   * This is the CopilotKit-sanctioned way to customize the header.
   */
  const HeaderComponent = useCallback(
    () => (
      <>
        <CustomHeader
          threads={threads}
          activeThreadId={activeThreadId}
          activeThreadTitle={activeThreadTitle}
          threadsCollapsed={threadsCollapsed}
          onToggleThreads={handleToggleThreadsCollapsed}
          onNewChat={handleStartNewChat}
          onSelectThread={handleSelectThread}
          onDeleteThread={handleDeleteThreadWithUrl}
          onClose={() => handleSetOpen(false)}
          sizeMode={sizeMode}
          onCycleSize={handleCycleSize}
          isMobile={isMobile}
        />
        {/* Thread not found notification */}
        {threadNotFoundMessage && (
          <div className={styles.notification}>
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm text-amber-700 dark:text-amber-300">{threadNotFoundMessage}</p>
              <button
                onClick={() => setThreadNotFoundMessage(null)}
                className="p-1 rounded hover:bg-amber-500/20 text-amber-600 dark:text-amber-400"
                title="Dismiss"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </>
    ),
    [
      threads,
      activeThreadId,
      activeThreadTitle,
      threadsCollapsed,
      handleToggleThreadsCollapsed,
      handleStartNewChat,
      handleSelectThread,
      handleDeleteThreadWithUrl,
      handleSetOpen,
      sizeMode,
      handleCycleSize,
      isMobile,
      threadNotFoundMessage,
    ]
  );

  // ============================================================================
  // Render
  // ============================================================================

  if (!mounted) return null;

  const wrapperClasses = cn(
    styles.wrapper,
    isOpen ? styles.open : styles.closed,
    !isMobile && sizeMode === "full" && styles.sizeFull
  );

  return (
    <>
      {/* Mobile overlay */}
      <div
        className={cn(styles.overlay, isOpen && isMobile && styles.visible)}
        onClick={() => handleSetOpen(false)}
      />

      {/* FAB button when closed */}
      {!isOpen && (
        <button
          onClick={() => handleSetOpen(true)}
          className={styles.fab}
          title="Open AI Assistant"
          aria-label="Open AI Assistant"
          data-testid="copilot-fab"
        >
          <MessageCircle className="w-6 h-6" />
        </button>
      )}

      {/* Main container */}
      <div
        className={wrapperClasses}
        style={{ ...(copilotStyles as React.CSSProperties), width: chatWidth }}
      >
        {/* Resize handle */}
        {!isMobile && sizeMode !== "full" && (
          <div
            className={cn(styles.resizeHandle, isResizing && styles.active)}
            onMouseDown={handleMouseDown}
            title="Drag to resize"
          />
        )}

        {/* Chat panel */}
        <div className={styles.container}>
          {/* CopilotKit Sidebar with custom Header */}
          <CKSidebar
            defaultOpen={true}
            clickOutsideToClose={false}
            Header={HeaderComponent}
            labels={{
              title: "AI Assistant",
              placeholder: "Ask about your videos...",
              initial: "How can I help you with your video library?",
            }}
          />
        </div>
      </div>
    </>
  );
}
