"use client";

/**
 * Copilot Actions Hook (Optimized)
 *
 * This is the main entry point for registering all Copilot tools and actions.
 *
 * Architecture:
 * - Pattern B (Backend Tools): The agent calls backend tools (query_library, search_videos, etc.)
 *   which run on the server with low latency. The frontend renders results via useBackendToolRenderers.
 *
 * - Pattern A (Frontend Tools): For UI-only operations (wizards, confirmations).
 *   Currently only used for simple utility operations.
 *
 * - Copilot Readable: Context provided to the agent (scope, current video)
 */

import { useCopilotReadable } from "@copilotkit/react-core";
import { useScope, useAISettings } from "@/app/providers";
import { useCallback } from "react";

// Modular hooks
import { useFrontendTools } from "./useFrontendTools";
import { useBackendToolRenderers } from "./useBackendToolRenderers";

// Re-export types for consumers
export type {
  Evidence,
  RecommendedVideo,
  QueryResponse,
  CoverageResponse,
  ScoredSegment,
  SegmentSearchResponse,
} from "@/types/copilot-types";

// Re-export utils
export { formatTime, API_URL } from "./copilot-utils";

/**
 * Main hook to register all Copilot actions.
 *
 * This hook:
 * 1. Provides readable context to the agent (scope, AI settings)
 * 2. Registers backend tool renderers (Pattern B) - PRIMARY
 * 3. Registers remaining frontend tools (Pattern A) - utility operations
 */
export function useCopilotActions() {
  const { scope } = useScope();
  const { settings: aiSettings } = useAISettings();

  // =============================================================================
  // Copilot Readable Context
  // =============================================================================

  // Provide current scope to the agent - THIS CONTROLS WHAT TO SEARCH
  useCopilotReadable({
    description:
      "The current search scope filters. IMPORTANT: This controls what videos to search. " +
      "If videoIds is set, ONLY search those videos. " +
      "If channels is set, ONLY search videos from those channels. " +
      "If empty ({}), search the ENTIRE library.",
    value: scope,
  });

  // Provide AI knowledge settings to the agent
  useCopilotReadable({
    description:
      "AI knowledge source settings that control what the agent can use to answer questions. " +
      "useVideoContext: Whether to search the video library for context (RAG retrieval). " +
      "useLLMKnowledge: Whether the AI can use its general trained knowledge in answers. " +
      "useWebSearch: Whether to search the web for current information. " +
      "IMPORTANT: Pass these settings to the query_library tool to respect user preferences.",
    value: aiSettings,
  });

  // =============================================================================
  // Register Tools
  // =============================================================================

  // Pattern B: Backend tool renderers (PRIMARY - low latency)
  // The agent calls query_library, search_videos, etc. on the backend
  // These renderers display the results with rich UI
  useBackendToolRenderers();

  // Pattern A: Frontend tools (utility operations)
  // These are simple tools that don't benefit from agent orchestration
  useFrontendTools();
}

// =============================================================================
// Additional Hooks
// =============================================================================

/**
 * Hook to fetch coverage data imperatively.
 * Use this when you need coverage data outside of the Copilot context.
 */
export function useCoverage() {
  const { scope } = useScope();
  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const fetchCoverage = useCallback(async () => {
    const response = await fetch(`${API_URL}/api/v1/copilot/coverage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope }),
    });

    if (!response.ok) {
      throw new Error(`Coverage failed: ${response.statusText}`);
    }

    return response.json();
  }, [scope, API_URL]);

  return { fetchCoverage };
}
