"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import { CopilotVideoCard } from "./CopilotVideoCard";
import { FollowupButtons } from "./FollowupButtons";
import { UncertaintyMessage } from "./UncertaintyMessage";
import { useVideoContext, useScope } from "@/app/providers";
import { formatDuration } from "@/utils/formatDuration";

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

interface KeyMoment {
  timestamp: string;
  description: string;
  segmentId?: string | null;
  youTubeUrl?: string | null;
}

interface VideoExplanation {
  summary: string;
  keyMoments: KeyMoment[];
  relatedTo?: string | null;
}

interface RecommendedVideo {
  videoId: string;
  youTubeVideoId: string;
  title: string;
  channelName: string;
  thumbnailUrl?: string | null;
  duration?: number | null;
  relevanceScore: number;
  primaryReason: string;
  explanation?: VideoExplanation | null;
}

interface QueryScope {
  videoIds?: string[];
  channels?: string[];
  facets?: string[];
}

interface AISettingsEcho {
  useVideoContext: boolean;
  useLLMKnowledge: boolean;
  useWebSearch: boolean;
}

interface CopilotMessageProps {
  answer: string;
  evidence?: Evidence[];
  videoCards?: RecommendedVideo[];
  followups?: string[];
  uncertainty?: string | null;
  scopeEcho?: QueryScope | null;
  aiSettingsEcho?: AISettingsEcho | null;
  onFollowupClick?: (suggestion: string) => void;
}

/**
 * Custom react-markdown components for copilot message styling
 */
const markdownComponents: Components = {
  // Style source headers like "**From your videos:**" specially
  strong: ({ children }) => {
    const text = String(children).toLowerCase();
    const isSourceHeader = text.includes('from your videos') || 
                          text.includes('from ai knowledge');
    
    return (
      <strong 
        className={isSourceHeader 
          ? "font-semibold text-[var(--copilot-kit-primary-color)] block mt-3 first:mt-0 mb-1" 
          : "font-semibold"
        }
      >
        {children}
      </strong>
    );
  },
  // Keep paragraphs simple without extra margins
  p: ({ children }) => (
    <span className="block mb-2 last:mb-0">{children}</span>
  ),
};

/**
 * CopilotMessage Component
 * 
 * Renders the rich UI for tool call results in the chat interface.
 * This component is used by useRenderToolCall in useBackendToolRenderers.tsx.
 * 
 * ## Rich UI Elements
 * - Video cards with thumbnails and relevance scores
 * - Answer text rendered with react-markdown
 * - Sources section from structured evidence data
 * - Follow-up question buttons
 * 
 * ## Text Size Note
 * The answer text uses `text-base` (16px) for better readability.
 * Previously `text-sm` (14px) was too small for comfortable reading.
 * 
 * @see useBackendToolRenderers.tsx - registers this component with useRenderToolCall
 * @see threadPersistence.ts - prepareMessagesForDisplay reconstructs toolCalls for this to render
 * @see globals.css - CSS that hides CopilotKit's duplicate markdown text
 */
export function CopilotMessage({
  answer,
  evidence = [],
  videoCards = [],
  followups = [],
  uncertainty,
  scopeEcho,
  aiSettingsEcho,
  onFollowupClick,
}: CopilotMessageProps) {
  // Get current video and scope context for scope-aware uncertainty messages
  const { currentVideo } = useVideoContext();
  const { scope, clearScope } = useScope();
  
  // Check if we have a narrow scope (video-specific or filtered)
  const hasNarrowScope = 
    (scope.videoIds && scope.videoIds.length > 0) ||
    (scope.channels && scope.channels.length > 0) ||
    (scope.facets && scope.facets.length > 0);
  
  // Handler to broaden scope and potentially retry query
  const handleBroadenScope = () => {
    clearScope();
    // The user can ask their question again now that scope is cleared
  };
  
  // State for expand/collapse of related videos
  const [isVideosExpanded, setIsVideosExpanded] = useState(false);
  
  // Show 3 videos by default, all when expanded
  const visibleVideos = isVideosExpanded ? videoCards : videoCards.slice(0, 3);
  const hasMoreVideos = videoCards.length > 3;
  
  // Build knowledge sources badge content
  const knowledgeSources: string[] = [];
  if (aiSettingsEcho) {
    if (aiSettingsEcho.useVideoContext) knowledgeSources.push('Your Videos');
    if (aiSettingsEcho.useLLMKnowledge) knowledgeSources.push('AI Knowledge');
  }
  
  // Derive scope level from scopeEcho object
  const deriveScopeLevel = (): { label: string; icon: 'video' | 'channel' | 'library' } | null => {
    if (!scopeEcho) return null;
    
    // If specific videos are scoped, it's video-level
    if (scopeEcho.videoIds && scopeEcho.videoIds.length > 0) {
      return { 
        label: scopeEcho.videoIds.length === 1 ? 'This Video' : `${scopeEcho.videoIds.length} Videos`,
        icon: 'video'
      };
    }
    
    // If channels are specified, it's channel-level
    if (scopeEcho.channels && scopeEcho.channels.length > 0) {
      return { 
        label: scopeEcho.channels.length === 1 ? 'This Channel' : `${scopeEcho.channels.length} Channels`,
        icon: 'channel'
      };
    }
    
    // Default to full library
    return { label: 'All Videos', icon: 'library' };
  };
  
  const scopeInfo = deriveScopeLevel();
  
  return (
    <div className="w-full space-y-3 animate-in fade-in duration-200">
      {/* Uncertainty warning if present */}
      {uncertainty && (
        <UncertaintyMessage 
          message={uncertainty}
          showBroadenOption={hasNarrowScope}
          currentVideoTitle={currentVideo?.title}
          onBroadenScope={handleBroadenScope}
        />
      )}

      {/* Knowledge sources badge row - compact indicator of what sources were used */}
      {(knowledgeSources.length > 0 || scopeInfo) && (
        <div className="flex items-center gap-2 text-xs text-[var(--copilot-kit-muted-color)]">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <span>Searched:</span>
          {knowledgeSources.map((source, idx) => (
            <span key={source} className="inline-flex items-center gap-1">
              {idx > 0 && <span className="text-[var(--copilot-kit-separator-color)]">•</span>}
              <span className="font-medium text-[var(--copilot-kit-secondary-contrast-color)]">{source}</span>
            </span>
          ))}
          {scopeInfo && (
            <>
              <span className="text-[var(--copilot-kit-separator-color)] mx-1">|</span>
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-[var(--copilot-kit-primary-color)]/10 border border-[var(--copilot-kit-primary-color)]/20">
                {scopeInfo.icon === 'video' && (
                  <svg className="w-3 h-3 text-[var(--copilot-kit-primary-color)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 4v16M17 4v16M3 8h4m10 0h4M3 12h18M3 16h4m10 0h4M4 20h16a1 1 0 001-1V5a1 1 0 00-1-1H4a1 1 0 00-1 1v14a1 1 0 001 1z" />
                  </svg>
                )}
                {scopeInfo.icon === 'channel' && (
                  <svg className="w-3 h-3 text-[var(--copilot-kit-primary-color)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                  </svg>
                )}
                {scopeInfo.icon === 'library' && (
                  <svg className="w-3 h-3 text-[var(--copilot-kit-primary-color)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                )}
                <span className="font-medium text-[var(--copilot-kit-primary-color)]">{scopeInfo.label}</span>
              </span>
            </>
          )}
        </div>
      )}

      {/* Video cards - primary visual display */}
      {videoCards.length > 0 && (
        <div className="space-y-3 bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)]">
          <div className="flex items-center gap-2.5">
            <div className="w-5 h-5 rounded-lg bg-gradient-to-br from-red-500 to-rose-600 flex items-center justify-center shadow-sm">
              <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 24 24">
                <path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.816v-8l8 3.993-8 4.007z"/>
              </svg>
            </div>
            <span className="text-sm font-semibold text-[var(--copilot-kit-secondary-contrast-color)]">
              Related Videos
            </span>
            <span className="text-xs font-medium text-[var(--copilot-kit-primary-color)] bg-[var(--copilot-kit-primary-color)]/10 px-2 py-0.5 rounded-full border border-[var(--copilot-kit-primary-color)]/20">
              {videoCards.length}
            </span>
            {hasMoreVideos && (
              <button
                onClick={() => setIsVideosExpanded(!isVideosExpanded)}
                className="ml-auto text-xs font-medium text-[var(--copilot-kit-muted-color)] hover:text-[var(--copilot-kit-primary-color)] transition-all duration-150 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-transparent hover:border-[var(--copilot-kit-separator-color)] hover:bg-[var(--copilot-kit-secondary-color)]"
              >
                {isVideosExpanded ? (
                  <>
                    <span>Show less</span>
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                    </svg>
                  </>
                ) : (
                  <>
                    <span>+{videoCards.length - 3} more</span>
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </>
                )}
              </button>
            )}
          </div>
          <div className="space-y-2">
            {visibleVideos.map((video, index) => (
              <div
                key={video.videoId}
                className="animate-in slide-in-from-left duration-300"
                style={{ animationDelay: `${index * 75}ms` }}
              >
                <CopilotVideoCard {...video} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Answer with react-markdown rendering */}
      {answer && (
        <div className="group bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)]">
          <div className="text-[var(--copilot-kit-secondary-contrast-color)] leading-relaxed text-base">
            <ReactMarkdown components={markdownComponents}>
              {answer}
            </ReactMarkdown>
          </div>
          
          {/* Sources from structured evidence data */}
          {evidence.length > 0 && (
            <div className="mt-3 pt-3 border-t border-[var(--copilot-kit-separator-color)]">
              <div className="flex items-center gap-2 mb-2">
                <svg className="w-4 h-4 text-[var(--copilot-kit-primary-color)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                <span className="text-sm font-semibold text-[var(--copilot-kit-secondary-contrast-color)]">Sources</span>
              </div>
              <ol className="space-y-2">
                {evidence.map((ev, index) => (
                  <li key={ev.segmentId} className="text-sm flex items-start gap-2 group/cite">
                    <span className="text-[var(--copilot-kit-primary-color)] font-semibold shrink-0 bg-[var(--copilot-kit-secondary-color)] rounded px-1.5 py-0.5 text-xs border border-[var(--copilot-kit-separator-color)]">[{index + 1}]</span>
                    <a
                      href={ev.youTubeUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[var(--copilot-kit-secondary-contrast-color)]/90 hover:text-[var(--copilot-kit-primary-color)] transition-colors truncate flex items-center gap-1"
                    >
                      <span className="font-medium text-xs">{ev.videoTitle}</span>
                      <span className="text-[10px] text-[var(--copilot-kit-muted-color)]">@ {formatDuration(ev.startTime)}</span>
                      <svg className="w-3 h-3 text-[var(--copilot-kit-muted-color)] group-hover/cite:text-[var(--copilot-kit-primary-color)] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}

      {/* Follow-up suggestions - always at the end */}
      {followups && followups.length > 0 && (
        <FollowupButtons
          suggestions={followups}
          onFollowupClick={onFollowupClick || (() => {})}
        />
      )}
    </div>
  );
}
