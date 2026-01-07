"use client";

/**
 * Frontend Tools (Pattern A)
 * 
 * These hooks register frontend-only tools for:
 * - UI interactions (wizards, confirmations)
 * - Client-side operations
 * 
 * NOTE: The main `query_library` tool is now a BACKEND tool (Pattern B).
 * See useBackendToolRenderers.tsx for the query_library renderer.
 */

import { useCopilotAction } from "@copilotkit/react-core";
import { useScope } from "@/app/providers";
import { apiPost, API_URL } from "./copilot-utils";
import type { SegmentSearchResponse, CoverageResponse } from "@/types/copilot-types";

/**
 * Register all frontend tools (Pattern A).
 * 
 * These are tools that need to run on the frontend only.
 * Most query/search operations are now backend tools for better latency.
 */
export function useFrontendTools() {
  // These remaining tools make direct API calls because they're 
  // simple operations that don't benefit from agent orchestration.
  // They can be migrated to backend tools in the future.
  useSearchSegmentsTool();
  useCoverageTool();
  useTopicsTool();
  useRelatedVideosTool();
}

// =============================================================================
// Search Segments Tool (candidate for backend migration)
// =============================================================================

function useSearchSegmentsTool() {
  const { scope } = useScope();

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
      return apiPost<SegmentSearchResponse>("/api/v1/copilot/search/segments", {
        queryText,
        scope,
        limit: Math.min(limit, 50),
      });
    },
  });
}

// =============================================================================
// Coverage Tool (candidate for backend migration)
// =============================================================================

function useCoverageTool() {
  const { scope } = useScope();

  useCopilotAction({
    name: "getCoverage",
    description:
      "Get statistics about what content is in the library. Use this when the user asks about library size or coverage.",
    parameters: [],
    handler: async () => {
      return apiPost<CoverageResponse>("/api/v1/copilot/coverage", { scope });
    },
  });
}

// =============================================================================
// Topics Tool (candidate for backend migration)
// =============================================================================

function useTopicsTool() {
  const { scope } = useScope();

  useCopilotAction({
    name: "getTopics",
    description:
      "Get the main topics/categories in the library. Use this when the user asks what topics are available.",
    parameters: [],
    handler: async () => {
      return apiPost("/api/v1/copilot/topics", { scope });
    },
  });
}

// =============================================================================
// Related Videos Tool
// =============================================================================

function useRelatedVideosTool() {
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
      return response.json();
    },
  });
}
