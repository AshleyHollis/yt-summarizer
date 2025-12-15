"use client";

import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";
import React, { createContext, useContext, useState, useCallback } from "react";

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

export function Providers({ children }: ProvidersProps) {
  // Self-hosted runtime using Microsoft Agent Framework
  // Configure NEXT_PUBLIC_API_URL to point to your backend
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const runtimeUrl = `${apiUrl}/api/copilotkit`;

  return (
    <CopilotKit runtimeUrl={runtimeUrl} agent="yt-summarizer">
      <VideoContextProvider>
        <ScopeProvider>{children}</ScopeProvider>
      </VideoContextProvider>
    </CopilotKit>
  );
}
