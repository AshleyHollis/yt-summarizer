"use client";

/**
 * Backend Tool Renderers (Pattern B)
 * 
 * These hooks use `useRenderToolCall` to render backend agent tool calls.
 * This is the proper CopilotKit API for rendering tool calls with custom UI.
 * 
 * The renderers react to AG-UI tool lifecycle events (TOOL_CALL_START,
 * TOOL_CALL_RESULT) and render appropriate UI.
 * 
 * ## CRITICAL: Tool Name Matching
 * 
 * The `name` parameter in useRenderToolCall MUST EXACTLY match:
 * 1. The tool name from the backend agent (Python: "query_library", snake_case)
 * 2. The inferred tool name in prepareMessagesForDisplay() for persisted threads
 * 
 * If these don't match, the rich UI won't render and you'll see:
 * - Blank messages (for new calls)
 * - Plain text instead of rich UI (for persisted threads)
 * 
 * Current registered tool names (snake_case):
 * - "query_library" - Primary RAG tool with answer, video cards, evidence
 * - "search_videos" - Search for videos
 * - "search_segments" - Search for transcript segments
 * - "get_library_coverage" - Get library topic coverage
 * - "get_video_summary" - Get single video summary
 * - "get_topics_for_channel" - Get topics for a channel
 * 
 * @see threadPersistence.ts - prepareMessagesForDisplay() infers tool names for persistence
 * @see globals.css - CSS that hides duplicate text when tool render is present
 * 
 * See: https://docs.copilotkit.ai/langgraph/generative-ui/backend-tools
 */

import { useRenderToolCall, useCopilotChat } from "@copilotkit/react-core";
import { TextMessage, MessageRole } from "@copilotkit/runtime-client-gql";
import { useCallback } from "react";
import { ToolLoadingState, isToolLoading, isToolComplete } from "@/components/copilot/ToolLoadingState";
import { CopilotVideoCard } from "@/components/copilot/CopilotVideoCard";
import { CopilotMessage } from "@/components/copilot/CopilotMessage";
import { formatTime } from "./copilot-utils";
import type { RecommendedVideo, ScoredSegment, CoverageResponse, Evidence } from "@/types/copilot-types";

// =============================================================================
// Backend Tool Renderers
// =============================================================================

/**
 * Register all backend tool renderers.
 * Call this once in your component to enable rich UI for backend tools.
 */
export function useBackendToolRenderers() {
  useQueryLibraryRenderer();  // PRIMARY - rich RAG response
  useSearchVideosRenderer();
  useSearchSegmentsRenderer();
  useLibraryCoverageRenderer();
  useVideoSummaryRenderer();
  useTopicsRenderer();
}

// =============================================================================
// Query Library Renderer (PRIMARY)
// =============================================================================

/**
 * Renderer for query_library backend tool - the primary RAG tool
 */
function useQueryLibraryRenderer() {
  const { appendMessage } = useCopilotChat();

  const handleFollowupClick = useCallback(
    async (suggestion: string) => {
      await appendMessage(
        new TextMessage({
          role: MessageRole.User,
          content: suggestion,
        })
      );
    },
    [appendMessage]
  );

  useRenderToolCall({
    name: "query_library",
    render: ({ status, result, args }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Searching your video library..."
            description={args?.query ? `Looking for: "${args.query}"` : "Finding relevant content"}
          />
        );
      }

      if (isToolComplete(status) && result) {
        // Filter low-relevance content
        const MIN_RELEVANCE = 0.50;
        const videoCards = (result.videoCards || []).filter(
          (v: RecommendedVideo) => v.relevanceScore >= MIN_RELEVANCE
        );
        const evidence = (result.evidence || []).filter(
          (e: Evidence) => e.confidence >= MIN_RELEVANCE
        );

        return (
          <CopilotMessage
            answer={result.answer || ""}
            evidence={evidence}
            videoCards={videoCards}
            followups={result.followups || []}
            uncertainty={result.uncertainty || null}
            scopeEcho={result.scopeEcho || null}
            aiSettingsEcho={result.aiSettingsEcho ? {
              useVideoContext: result.aiSettingsEcho.useVideoContext ?? true,
              useLLMKnowledge: result.aiSettingsEcho.useLLMKnowledge ?? true,
              useWebSearch: result.aiSettingsEcho.useWebSearch ?? false,
            } : null}
            onFollowupClick={handleFollowupClick}
          />
        );
      }

      return <></>;
    },
  });
}

// =============================================================================
// Individual Renderers
// =============================================================================

/**
 * Renderer for search_videos backend tool
 */
function useSearchVideosRenderer() {
  useRenderToolCall({
    name: "search_videos",
    render: ({ status, result, args }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Searching videos..."
            description={args?.query ? `Looking for "${args.query}"` : undefined}
          />
        );
      }

      if (isToolComplete(status) && result?.videos?.length > 0) {
        return (
          <div className="space-y-3">
            <div className="text-sm text-[var(--copilot-kit-muted-color)]">
              Found {result.videos.length} video{result.videos.length !== 1 ? 's' : ''}:
            </div>
            <div className="space-y-2">
              {result.videos.map((video: RecommendedVideo) => (
                <CopilotVideoCard
                  key={video.videoId}
                  videoId={video.videoId}
                  youTubeVideoId={video.youTubeVideoId}
                  title={video.title}
                  channelName={video.channelName}
                  thumbnailUrl={video.thumbnailUrl}
                  duration={video.duration}
                  relevanceScore={video.relevanceScore}
                  primaryReason={video.primaryReason}
                  explanation={video.explanation}
                />
              ))}
            </div>
          </div>
        );
      }

      return <></>;
    },
  });
}

/**
 * Renderer for search_segments backend tool
 */
function useSearchSegmentsRenderer() {
  useRenderToolCall({
    name: "search_segments",
    render: ({ status, result, args }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Searching transcripts..."
            description={args?.query ? `Looking for "${args.query}"` : undefined}
          />
        );
      }

      if (isToolComplete(status) && result?.segments?.length > 0) {
        const segments = result.segments as ScoredSegment[];
        const displaySegments = segments.slice(0, 5);
        const remainingCount = segments.length - 5;

        return (
          <div className="space-y-3">
            <div className="text-sm text-[var(--copilot-kit-muted-color)]">
              Found {segments.length} transcript segment{segments.length !== 1 ? 's' : ''}:
            </div>
            <div className="space-y-2">
              {displaySegments.map((segment) => (
                <SegmentCard key={segment.segmentId} segment={segment} />
              ))}
              {remainingCount > 0 && (
                <div className="text-xs text-[var(--copilot-kit-muted-color)] text-center">
                  ...and {remainingCount} more
                </div>
              )}
            </div>
          </div>
        );
      }

      return <></>;
    },
  });
}

/**
 * Renderer for get_library_coverage backend tool
 */
function useLibraryCoverageRenderer() {
  useRenderToolCall({
    name: "get_library_coverage",
    render: ({ status, result }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Checking library coverage..."
            description="Counting videos and segments"
          />
        );
      }

      if (isToolComplete(status) && result) {
        const coverage = result as CoverageResponse;
        return <CoverageCard coverage={coverage} />;
      }

      return <></>;
    },
  });
}

/**
 * Renderer for get_video_summary backend tool
 */
function useVideoSummaryRenderer() {
  useRenderToolCall({
    name: "get_video_summary",
    render: ({ status }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Loading video summary..."
            description="Fetching key points"
          />
        );
      }
      return <></>;
    },
  });
}

/**
 * Renderer for get_topics_for_channel backend tool
 */
function useTopicsRenderer() {
  useRenderToolCall({
    name: "get_topics_for_channel",
    render: ({ status }) => {
      if (isToolLoading(status)) {
        return (
          <ToolLoadingState
            title="Analyzing topics..."
            description="Finding covered subjects"
          />
        );
      }
      return <></>;
    },
  });
}

// =============================================================================
// Helper Components (internal)
// =============================================================================

function SegmentCard({ segment }: { segment: ScoredSegment }) {
  return (
    <div className="p-3 bg-[var(--copilot-kit-secondary-color)]/50 rounded-lg border border-[var(--copilot-kit-separator-color)]">
      <div className="flex items-start justify-between gap-2 mb-1">
        <span className="text-sm font-medium text-[var(--copilot-kit-secondary-contrast-color)] line-clamp-1">
          {segment.videoTitle}
        </span>
        {segment.youTubeUrl && (
          <a
            href={segment.youTubeUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-[var(--copilot-kit-primary-color)] hover:underline whitespace-nowrap"
          >
            {formatTime(segment.startTime)}
          </a>
        )}
      </div>
      <p className="text-xs text-[var(--copilot-kit-muted-color)] line-clamp-2">
        {segment.text}
      </p>
    </div>
  );
}

function CoverageCard({ coverage }: { coverage: CoverageResponse }) {
  return (
    <div className="p-4 bg-[var(--copilot-kit-secondary-color)]/50 rounded-xl border border-[var(--copilot-kit-separator-color)]">
      <div className="text-sm font-medium text-[var(--copilot-kit-secondary-contrast-color)] mb-3">
        📊 Library Coverage
      </div>
      <div className="grid grid-cols-3 gap-3 text-center">
        <StatCard value={coverage.videoCount ?? 0} label="Videos" />
        <StatCard value={coverage.segmentCount ?? 0} label="Segments" />
        <StatCard value={coverage.channelCount ?? 0} label="Channels" />
      </div>
    </div>
  );
}

function StatCard({ value, label }: { value: number; label: string }) {
  return (
    <div className="p-2 bg-[var(--copilot-kit-background-color)] rounded-lg">
      <div className="text-lg font-bold text-[var(--copilot-kit-primary-color)]">
        {value}
      </div>
      <div className="text-xs text-[var(--copilot-kit-muted-color)]">{label}</div>
    </div>
  );
}
