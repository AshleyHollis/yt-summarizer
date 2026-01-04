"use client";

import React, { createContext, useContext, useState, useCallback, useMemo } from "react";
import type { VideoCard as VideoCardType } from "@/services/api";

/**
 * Minimal video info stored in selection (to avoid stale data)
 */
export interface SelectedVideo {
  video_id: string;
  title: string;
  thumbnail_url: string | null;
  youtube_video_id: string;
}

interface VideoSelectionContextType {
  /** Currently selected videos */
  selectedVideos: SelectedVideo[];
  /** Whether selection mode is active */
  selectionMode: boolean;
  /** Check if a video is selected */
  isSelected: (videoId: string) => boolean;
  /** Toggle video selection */
  toggleSelection: (video: SelectedVideo) => void;
  /** Add video to selection */
  addToSelection: (video: SelectedVideo) => void;
  /** Remove video from selection */
  removeFromSelection: (videoId: string) => void;
  /** Clear all selections */
  clearSelection: () => void;
  /** Enter selection mode */
  enterSelectionMode: () => void;
  /** Exit selection mode and clear */
  exitSelectionMode: () => void;
}

const VideoSelectionContext = createContext<VideoSelectionContextType | undefined>(undefined);

export function useVideoSelection(): VideoSelectionContextType {
  const context = useContext(VideoSelectionContext);
  if (!context) {
    throw new Error("useVideoSelection must be used within a VideoSelectionProvider");
  }
  return context;
}

/**
 * Convert a full VideoCard to minimal SelectedVideo
 */
export function toSelectedVideo(video: VideoCardType): SelectedVideo {
  return {
    video_id: video.video_id,
    title: video.title,
    thumbnail_url: video.thumbnail_url,
    youtube_video_id: video.youtube_video_id,
  };
}

interface VideoSelectionProviderProps {
  children: React.ReactNode;
}

export function VideoSelectionProvider({ children }: VideoSelectionProviderProps) {
  const [selectedVideos, setSelectedVideos] = useState<SelectedVideo[]>([]);
  const [selectionMode, setSelectionMode] = useState(false);

  const isSelected = useCallback(
    (videoId: string) => selectedVideos.some((v) => v.video_id === videoId),
    [selectedVideos]
  );

  const toggleSelection = useCallback((video: SelectedVideo) => {
    setSelectedVideos((prev) => {
      const exists = prev.some((v) => v.video_id === video.video_id);
      if (exists) {
        return prev.filter((v) => v.video_id !== video.video_id);
      }
      return [...prev, video];
    });
  }, []);

  const addToSelection = useCallback((video: SelectedVideo) => {
    setSelectedVideos((prev) => {
      if (prev.some((v) => v.video_id === video.video_id)) {
        return prev;
      }
      return [...prev, video];
    });
  }, []);

  const removeFromSelection = useCallback((videoId: string) => {
    setSelectedVideos((prev) => prev.filter((v) => v.video_id !== videoId));
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedVideos([]);
  }, []);

  const enterSelectionMode = useCallback(() => {
    setSelectionMode(true);
  }, []);

  const exitSelectionMode = useCallback(() => {
    setSelectionMode(false);
    setSelectedVideos([]);
  }, []);

  const value = useMemo(
    () => ({
      selectedVideos,
      selectionMode,
      isSelected,
      toggleSelection,
      addToSelection,
      removeFromSelection,
      clearSelection,
      enterSelectionMode,
      exitSelectionMode,
    }),
    [
      selectedVideos,
      selectionMode,
      isSelected,
      toggleSelection,
      addToSelection,
      removeFromSelection,
      clearSelection,
      enterSelectionMode,
      exitSelectionMode,
    ]
  );

  return (
    <VideoSelectionContext.Provider value={value}>
      {children}
    </VideoSelectionContext.Provider>
  );
}
