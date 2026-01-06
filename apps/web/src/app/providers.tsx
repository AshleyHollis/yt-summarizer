"use client";

import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";
import { ThemeProvider } from "next-themes";
import React, { createContext, useContext, useState, useCallback, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { ToolResultProvider } from "@/contexts/ToolResultContext";
import { HealthStatusProvider, useHealthStatus } from "@/contexts/HealthStatusContext";
import { WarmingUpIndicator } from "@/components/common";

// Types for scope management
export interface DateRange {
  from?: string;
  to?: string;
}

export interface QueryScope {
  channels?: string[];
  videoIds?: string[];
  dateRange?: DateRange;
  facets?: string[];
  contentTypes?: ("summary" | "segment" | "relationship")[];
}

// Types for AI knowledge source settings
export interface AIKnowledgeSettings {
  useVideoContext: boolean;  // Search video library for context
  useLLMKnowledge: boolean;  // Allow LLM to use its trained knowledge
  useWebSearch: boolean;     // Enable web search for current information
}

export interface AISettingsContextType {
  settings: AIKnowledgeSettings;
  updateSettings: (partial: Partial<AIKnowledgeSettings>) => void;
  toggleSetting: (key: keyof AIKnowledgeSettings) => void;
}

const AISettingsContext = createContext<AISettingsContextType | undefined>(undefined);

export function useAISettings(): AISettingsContextType {
  const context = useContext(AISettingsContext);
  if (!context) {
    throw new Error("useAISettings must be used within an AISettingsProvider");
  }
  return context;
}

function AISettingsProvider({ children }: { children: React.ReactNode }) {
  const [settings, setSettings] = useState<AIKnowledgeSettings>({
    useVideoContext: true,
    useLLMKnowledge: true,
    useWebSearch: false,
  });

  const updateSettings = useCallback((partial: Partial<AIKnowledgeSettings>) => {
    setSettings((prev) => ({ ...prev, ...partial }));
  }, []);

  const toggleSetting = useCallback((key: keyof AIKnowledgeSettings) => {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  return (
    <AISettingsContext.Provider value={{ settings, updateSettings, toggleSetting }}>
      {children}
    </AISettingsContext.Provider>
  );
}

// Types for current video context (when viewing a specific video)
export interface CurrentVideoContext {
  videoId: string;
  title: string;
  channelName: string;
  youtubeVideoId?: string;
  summary?: string;
}

export interface VideoContextType {
  currentVideo: CurrentVideoContext | null;
  setCurrentVideo: (video: CurrentVideoContext | null) => void;
}

const VideoContext = createContext<VideoContextType | undefined>(undefined);

export function useVideoContext(): VideoContextType {
  const context = useContext(VideoContext);
  if (!context) {
    throw new Error("useVideoContext must be used within a VideoContextProvider");
  }
  return context;
}

function VideoContextProvider({ children }: { children: React.ReactNode }) {
  const [currentVideo, setCurrentVideo] = useState<CurrentVideoContext | null>(null);

  return (
    <VideoContext.Provider value={{ currentVideo, setCurrentVideo }}>
      {children}
    </VideoContext.Provider>
  );
}

export interface ScopeContextType {
  scope: QueryScope;
  setScope: (scope: QueryScope) => void;
  updateScope: (partial: Partial<QueryScope>) => void;
  clearScope: () => void;
  addChannel: (channelId: string) => void;
  removeChannel: (channelId: string) => void;
  addVideo: (videoId: string) => void;
  removeVideo: (videoId: string) => void;
  addFacet: (facetId: string) => void;
  removeFacet: (facetId: string) => void;
}

const ScopeContext = createContext<ScopeContextType | undefined>(undefined);

export function useScope(): ScopeContextType {
  const context = useContext(ScopeContext);
  if (!context) {
    throw new Error("useScope must be used within a ScopeProvider");
  }
  return context;
}

function ScopeProvider({ children }: { children: React.ReactNode }) {
  const [scope, setScope] = useState<QueryScope>({});

  const updateScope = useCallback((partial: Partial<QueryScope>) => {
    setScope((prev) => ({ ...prev, ...partial }));
  }, []);

  const clearScope = useCallback(() => {
    setScope({});
  }, []);

  const addChannel = useCallback((channelId: string) => {
    setScope((prev) => ({
      ...prev,
      channels: [...(prev.channels || []), channelId],
    }));
  }, []);

  const removeChannel = useCallback((channelId: string) => {
    setScope((prev) => ({
      ...prev,
      channels: (prev.channels || []).filter((id) => id !== channelId),
    }));
  }, []);

  const addVideo = useCallback((videoId: string) => {
    setScope((prev) => ({
      ...prev,
      videoIds: [...(prev.videoIds || []), videoId],
    }));
  }, []);

  const removeVideo = useCallback((videoId: string) => {
    setScope((prev) => ({
      ...prev,
      videoIds: (prev.videoIds || []).filter((id) => id !== videoId),
    }));
  }, []);

  const addFacet = useCallback((facetId: string) => {
    setScope((prev) => ({
      ...prev,
      facets: [...(prev.facets || []), facetId],
    }));
  }, []);

  const removeFacet = useCallback((facetId: string) => {
    setScope((prev) => ({
      ...prev,
      facets: (prev.facets || []).filter((id) => id !== facetId),
    }));
  }, []);

  return (
    <ScopeContext.Provider
      value={{
        scope,
        setScope,
        updateScope,
        clearScope,
        addChannel,
        removeChannel,
        addVideo,
        removeVideo,
        addFacet,
        removeFacet,
      }}
    >
      {children}
    </ScopeContext.Provider>
  );
}

interface ProvidersProps {
  children: React.ReactNode;
}

/**
 * Root Providers Component
 * 
 * ## CHAT WINDOW / THREAD ARCHITECTURE
 * 
 * This is where CopilotKit is initialized. Understanding this is CRITICAL
 * to avoid breaking the chat/thread functionality.
 * 
 * ### Key Components and Their Roles:
 * 
 * 1. **CopilotKit** (this file)
 *    - Initializes the CopilotKit runtime connection
 *    - Receives `threadId` from URL to load correct thread
 *    - ⚠️ DO NOT use `key={threadId}` - causes full remount and UI flash
 * 
 * 2. **ThreadedCopilotSidebar** (components/copilot/ThreadedCopilotSidebar.tsx)
 *    - The actual chat UI component
 *    - Manages thread list dropdown and switching
 *    - Uses useThreadPersistence hook for thread operations
 * 
 * 3. **useThreadPersistence** (hooks/useThreadPersistence.ts)
 *    - React hook for all thread CRUD operations
 *    - Handles debounced auto-save of messages
 *    - Syncs thread ID with URL via callback
 * 
 * 4. **threadPersistence.ts** (services/threadPersistence.ts)
 *    - Stateless API layer for server communication
 *    - prepareMessagesForDisplay() - reconstructs toolCalls for rich UI
 *    - copilotToThreadMessages() - converts CopilotKit messages for saving
 * 
 * ### Data Flow:
 * 
 * ```
 * URL (?thread=xxx)
 *   ↓
 * Providers.tsx → threadId prop to CopilotKit
 *   ↓
 * CopilotKit loads messages internally
 *   ↓
 * ThreadedCopilotSidebar displays via useCopilotChatInternal
 *   ↓
 * useThreadPersistence syncs URL ↔ saves messages
 * ```
 * 
 * ### Common Mistakes to Avoid:
 * 
 * ❌ Using `key={threadId}` on CopilotKit - causes full component remount
 * ❌ Managing threadId in React state instead of URL - causes sync issues
 * ❌ Calling setMessages without prepareMessagesForDisplay - breaks rich UI
 * ❌ Saving messages without copilotToThreadMessages - loses tool call info
 * 
 * @see ThreadedCopilotSidebar.tsx - Chat UI component
 * @see useThreadPersistence.ts - Thread operations hook
 * @see threadPersistence.ts - API layer and message transformation
 */
export function Providers({ children }: ProvidersProps) {
  // Self-hosted runtime using Microsoft Agent Framework
  // Configure NEXT_PUBLIC_API_URL to point to your backend
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const runtimeUrl = `${apiUrl}/api/copilotkit`;
  
  // ============================================================================
  // THREAD ID FROM URL - The Single Source of Truth
  // ============================================================================
  // Thread ID flows: URL → CopilotKit → ThreadedCopilotSidebar
  // Changes flow: ThreadedCopilotSidebar → URL → re-render with new threadId
  const searchParams = useSearchParams();
  const urlThreadId = searchParams.get("thread");
  
  // Track mounted state for hydration
  const [mounted, setMounted] = useState(false);
  
  useEffect(() => {
    setMounted(true);
  }, []);

  // Always render CopilotKit, but wait for client-side mount
  // to avoid hydration mismatch with threadId
  // ThreadedCopilotSidebar handles creating threads and updating the URL
  // NOTE: We intentionally DO NOT use key={threadId} here!
  // Using key causes full component remount which destroys UI state and
  // causes the "page refresh" effect. CopilotKit handles threadId changes internally.
  
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <HealthStatusProvider pollInterval={5000}>
        <HealthStatusBanner />
        <CopilotKit 
          runtimeUrl={runtimeUrl} 
          agent="yt-summarizer" 
          showDevConsole={false}
          enableInspector={false}
          threadId={mounted ? (urlThreadId || undefined) : undefined}
        >
          <ToolResultProvider>
            <VideoContextProvider>
              <ScopeProvider>
                <AISettingsProvider>{children}</AISettingsProvider>
              </ScopeProvider>
            </VideoContextProvider>
          </ToolResultProvider>
        </CopilotKit>
      </HealthStatusProvider>
    </ThemeProvider>
  );
}

/**
 * Component that reads health status from context and shows the warming up indicator.
 */
function HealthStatusBanner() {
  const { health, isDegraded, isUnhealthy } = useHealthStatus();
  
  if (!isDegraded && !isUnhealthy) {
    return null;
  }
  
  return (
    <WarmingUpIndicator 
      status={health?.status || 'unhealthy'} 
      show={isDegraded || isUnhealthy}
    />
  );
}
