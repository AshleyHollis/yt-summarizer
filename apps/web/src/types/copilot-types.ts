/**
 * Shared types for Copilot actions.
 *
 * These types match the API response schemas and are used by both
 * frontend tools (Pattern A) and backend tool renderers (Pattern B).
 */

import { QueryScope } from "@/app/providers";

// =============================================================================
// Evidence & Citations
// =============================================================================

export interface Evidence {
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

// =============================================================================
// Video Types
// =============================================================================

export interface KeyMoment {
  timestamp: string;
  description: string;
  segmentId?: string | null;
  youTubeUrl?: string | null;
}

export interface VideoExplanation {
  summary: string;
  keyMoments: KeyMoment[];
  relatedTo?: string | null;
}

export interface RecommendedVideo {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string;
  duration?: number;
  relevanceScore: number;
  primaryReason: string;
  explanation?: VideoExplanation | null;
}

// =============================================================================
// Segment Types
// =============================================================================

export interface ScoredSegment {
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

// =============================================================================
// API Response Types
// =============================================================================

export interface QueryResponse {
  answer: string;
  videoCards: RecommendedVideo[];
  evidence: Evidence[];
  scopeEcho: QueryScope | null;
  followups: string[];
  uncertainty: string | null;
  correlationId: string | null;
}

export interface SegmentSearchResponse {
  segments: ScoredSegment[];
  scopeEcho: QueryScope | null;
}

export interface CoverageResponse {
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

export interface TopicsResponse {
  topics: Array<{
    name: string;
    count: number;
    description?: string;
  }>;
  scopeEcho: QueryScope | null;
}

// =============================================================================
// Tool Status Types
// =============================================================================

export type ToolStatus = "inProgress" | "executing" | "complete" | "error";

export interface ToolRenderProps<TArgs = Record<string, unknown>, TResult = unknown> {
  status: ToolStatus;
  args?: TArgs;
  result?: TResult;
}
