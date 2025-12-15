"use client";

import { useCopilotAction, useCopilotReadable } from "@copilotkit/react-core";
import { useScope, useVideoContext, QueryScope } from "@/app/providers";
import { useCallback } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Evidence {
  videoId: string;
  youTubeVideoId: string;
  videoTitle: string;
  segmentId: string;
  segmentText: string;
  startTime: number;
  endTime: number;
  youTubeUrl: string;
  confidence: number;
}

interface RecommendedVideo {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string;
  duration?: number;
  relevanceScore: number;
  primaryReason: string;
}

interface QueryResponse {
  answer: string;
  videoCards: RecommendedVideo[];
  evidence: Evidence[];
  scopeEcho: QueryScope | null;
  followups: string[];
  uncertainty: string | null;
  correlationId: string | null;
}

interface ScoredSegment {
  segmentId: string;
  videoId: string;
  videoTitle: string;
  channelName: string;
  text: string;
  startTime: number;
  endTime: number;
  youTubeUrl: string;
  score: number;
}

interface SegmentSearchResponse {
  segments: ScoredSegment[];
  scopeEcho: QueryScope | null;
}

interface CoverageResponse {
  videoCount: number;
  segmentCount: number;
  channelCount: number;
  dateRange?: {
    earliest?: string;
    latest?: string;
  };
  lastUpdatedAt?: string;
  scopeEcho: QueryScope | null;
}

export function useCopilotActions() {
  const { scope } = useScope();
  const { currentVideo } = useVideoContext();

  // Make the current scope readable by the copilot
  useCopilotReadable({
    description: "The current search scope filters",
    value: scope,
  });

  // Make the currently viewed video readable by the copilot
  useCopilotReadable({
    description: "The video the user is currently viewing. When the user asks a question, they are likely asking about THIS video. Use the videoId and title to search for relevant content. If null, the user is on the library page and not viewing a specific video.",
    value: currentVideo,
  });

  // Action: Query the library
  useCopilotAction({
    name: "queryLibrary",
    description:
      "Search the video library and get answers with citations. Use this when the user asks a question about video content.",
    parameters: [
      {
        name: "query",
        type: "string",
        description: "The question to ask about the video library",
        required: true,
      },
    ],
    handler: async ({ query }) => {
      const response = await fetch(`${API_URL}/api/v1/copilot/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query,
          scope: scope,
        }),
      });

      if (!response.ok) {
        throw new Error(`Query failed: ${response.statusText}`);
      }

      const data: QueryResponse = await response.json();
      return data;
    },
  });

  // Action: Search segments
  useCopilotAction({
    name: "searchSegments",
    description:
      "Search for specific transcript segments using semantic search. Use this to find exact quotes or mentions.",
    parameters: [
      {
        name: "queryText",
        type: "string",
        description: "The text to search for in video transcripts",
        required: true,
      },
      {
        name: "limit",
        type: "number",
        description: "Maximum number of results (default 10, max 50)",
        required: false,
      },
    ],
    handler: async ({ queryText, limit = 10 }) => {
      const response = await fetch(`${API_URL}/api/v1/copilot/search/segments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queryText,
          scope,
          limit: Math.min(limit, 50),
        }),
      });

      if (!response.ok) {
        throw new Error(`Search failed: ${response.statusText}`);
      }

      const data: SegmentSearchResponse = await response.json();
      return data;
    },
  });

  // Action: Get library coverage
  useCopilotAction({
    name: "getCoverage",
    description:
      "Get statistics about what content is in the library. Use this when the user asks about library size or coverage.",
    parameters: [],
    handler: async () => {
      const response = await fetch(`${API_URL}/api/v1/copilot/coverage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope }),
      });

      if (!response.ok) {
        throw new Error(`Coverage failed: ${response.statusText}`);
      }

      const data: CoverageResponse = await response.json();
      return data;
    },
  });

  // Action: Get topics in scope
  useCopilotAction({
    name: "getTopics",
    description:
      "Get the main topics/categories in the library. Use this when the user asks what topics are available.",
    parameters: [],
    handler: async () => {
      const response = await fetch(`${API_URL}/api/v1/copilot/topics`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope }),
      });

      if (!response.ok) {
        throw new Error(`Topics failed: ${response.statusText}`);
      }

      return await response.json();
    },
  });

  // Action: Get related videos
  useCopilotAction({
    name: "getRelatedVideos",
    description:
      "Find videos related to a specific video. Use this when the user wants to explore similar content.",
    parameters: [
      {
        name: "videoId",
        type: "string",
        description: "The ID of the video to find related content for",
        required: true,
      },
      {
        name: "limit",
        type: "number",
        description: "Maximum number of related videos (default 10)",
        required: false,
      },
    ],
    handler: async ({ videoId, limit = 10 }) => {
      const response = await fetch(
        `${API_URL}/api/v1/copilot/neighbors/${videoId}?limit=${limit}`
      );

      if (!response.ok) {
        throw new Error(`Neighbors failed: ${response.statusText}`);
      }

      return await response.json();
    },
  });
}

// Hook to get coverage data
export function useCoverage() {
  const { scope } = useScope();

  const fetchCoverage = useCallback(async (): Promise<CoverageResponse> => {
    const response = await fetch(`${API_URL}/api/v1/copilot/coverage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope }),
    });

    if (!response.ok) {
      throw new Error(`Coverage failed: ${response.statusText}`);
    }

    return response.json();
  }, [scope]);

  return { fetchCoverage };
}
