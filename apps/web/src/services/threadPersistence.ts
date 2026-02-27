/**
 * Thread Persistence Service
 *
 * Centralized, deterministic service for managing chat thread persistence.
 * Uses idempotent operations and proper state machines to avoid race conditions.
 *
 * Design principles:
 * 1. Single source of truth - all thread state flows through this service
 * 2. Idempotent operations - safe to call multiple times
 * 3. Deterministic - no timeouts for core logic, only for user-facing debounce
 * 4. Atomic operations - server handles ID generation to avoid conflicts
 */

import { getApiBaseUrl } from './runtimeConfig';

// ============================================================================
// Types
// ============================================================================

export interface ChatThread {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messageCount: number;
  preview?: string;
  scope?: QueryScope | null;
  aiSettings?: AISettings | null;
}

export interface QueryScope {
  channels?: string[];
  videoIds?: string[];
  facets?: string[];
}

export interface AISettings {
  useVideoContext: boolean;
  useLLMKnowledge: boolean;
  useWebSearch: boolean;
}

export interface ThreadMessage {
  id: string;
  role: 'user' | 'assistant' | 'tool' | 'system';
  content?: string;
  toolCalls?: ToolCall[];
  toolCallId?: string;
}

interface ToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

// Server response types
interface ServerThread {
  thread_id: string;
  title: string | null;
  agent_name: string;
  message_count: number;
  created_at: string | null;
  updated_at: string | null;
}

interface ServerThreadDetail extends ServerThread {
  messages: ThreadMessage[];
  state: unknown | null;
  scope?: QueryScope | null;
  aiSettings?: AISettings | null;
}

// ============================================================================
// State Machine for Thread Creation
// ============================================================================

/**
 * Thread creation states - prevents duplicate creation attempts
 */
type CreationState = 'idle' | 'creating' | 'created';

class ThreadCreationTracker {
  private state: CreationState = 'idle';
  private pendingPromise: Promise<ChatThread | null> | null = null;

  /**
   * Check if we can start a new creation
   */
  canCreate(): boolean {
    return this.state === 'idle';
  }

  /**
   * Start creation and return the promise to wait on
   */
  startCreation(createFn: () => Promise<ChatThread | null>): Promise<ChatThread | null> {
    if (this.state !== 'idle') {
      // Already creating - return the existing promise
      return this.pendingPromise || Promise.resolve(null);
    }

    this.state = 'creating';
    this.pendingPromise = createFn()
      .then((result) => {
        this.state = result ? 'created' : 'idle';
        return result;
      })
      .catch((err) => {
        this.state = 'idle';
        throw err;
      });

    return this.pendingPromise;
  }

  /**
   * Reset to allow new creations (call when starting a fresh chat)
   */
  reset(): void {
    this.state = 'idle';
    this.pendingPromise = null;
  }
}

// Singleton instance for tracking thread creation
export const threadCreationTracker = new ThreadCreationTracker();

// ============================================================================
// CopilotKit Message Transformation
// ============================================================================

/**
 * Transform CopilotKit Message objects to ThreadMessage format for persistence.
 *
 * CopilotKit internal messages use these roles:
 * - "user": User text message
 * - "assistant": Can be either text OR a tool invocation (ID starts with "call_")
 * - "tool": Tool result message
 *
 * Our ThreadMessage format follows OpenAI's format:
 * - user/assistant/system messages have role and content
 * - assistant messages can have toolCalls array
 * - tool messages have toolCallId linking to the assistant's tool call
 */
export function copilotToThreadMessages(copilotMessages: unknown[]): ThreadMessage[] {
  const result: ThreadMessage[] = [];

  // Track tool call IDs we've seen in "assistant" messages that are actually tool invocations
  let lastToolCallId: string | null = null;

  for (const msg of copilotMessages) {
    const m = msg as Record<string, unknown>;
    const role = m.role as string;
    const id = (m.id as string) || crypto.randomUUID();
    const content = m.content as string | undefined;
    const name = m.name as string | undefined;
    const args = m.arguments as Record<string, unknown> | string | undefined;

    if (role === 'user' || role === 'system') {
      // User/system messages
      result.push({
        id,
        role: role as 'user' | 'system',
        content: content || '',
      });
    } else if (role === 'assistant') {
      // Check if this is a tool invocation (ID starts with "call_") or a regular assistant message
      const isToolInvocation = id.startsWith('call_') || name !== undefined;

      if (isToolInvocation) {
        // This is a tool invocation - add it as toolCalls on an assistant message
        const toolCall = {
          id,
          type: 'function' as const,
          function: {
            name: name || 'queryLibrary',
            arguments: typeof args === 'string' ? args : args ? JSON.stringify(args) : '{}',
          },
        };

        // Find or create an assistant message to attach this to
        const lastAssistantIdx = result.findLastIndex((msg) => msg.role === 'assistant');

        if (lastAssistantIdx >= 0 && !result[lastAssistantIdx].toolCalls?.length) {
          // Attach to existing assistant message that doesn't already have tool calls
          result[lastAssistantIdx].toolCalls = [toolCall];
          lastToolCallId = id;
        } else {
          // Create a new assistant message for this tool call
          result.push({
            id: `assistant-${id}`,
            role: 'assistant',
            content: '',
            toolCalls: [toolCall],
          });
          lastToolCallId = id;
        }
      } else {
        // Regular assistant text message
        result.push({
          id,
          role: 'assistant',
          content: content || '',
        });
      }
    } else if (role === 'tool') {
      // Tool result message - link to the last tool call we saw
      // CopilotKit may provide toolCallId or actionExecutionId, or we infer it
      const toolCallId =
        (m.toolCallId as string) || (m.actionExecutionId as string) || lastToolCallId || '';

      result.push({
        id,
        role: 'tool',
        content: content || '',
        toolCallId,
      });
    }
  }

  return result;
}

// ============================================================================
// API Operations (Idempotent)
// ============================================================================

/**
 * Convert server thread format to client format
 */
function serverToClient(server: ServerThread): ChatThread {
  return {
    id: server.thread_id,
    title: server.title || 'New Chat',
    createdAt: server.created_at ? new Date(server.created_at).getTime() : Date.now(),
    updatedAt: server.updated_at ? new Date(server.updated_at).getTime() : Date.now(),
    messageCount: server.message_count,
  };
}

/**
 * Convert server thread detail format to client format (includes scope and aiSettings)
 */
function serverDetailToClient(server: ServerThreadDetail): ChatThread {
  return {
    id: server.thread_id,
    title: server.title || 'New Chat',
    createdAt: server.created_at ? new Date(server.created_at).getTime() : Date.now(),
    updatedAt: server.updated_at ? new Date(server.updated_at).getTime() : Date.now(),
    messageCount: server.message_count,
    scope: server.scope || undefined,
    aiSettings: server.aiSettings || undefined,
  };
}

/**
 * Fetch all threads from server
 * Idempotent - safe to call multiple times
 */
export async function fetchThreads(): Promise<ChatThread[]> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads`);
  if (!response.ok) {
    throw new Error(`Failed to fetch threads: ${response.status}`);
  }
  const data = await response.json();
  const threads = (data.threads || []).map(serverToClient);
  // Filter out empty threads (incomplete/orphaned)
  return threads.filter((t: ChatThread) => t.messageCount > 0);
}

/**
 * Fetch a single thread with messages
 * Idempotent - safe to call multiple times
 */
export async function fetchThread(threadId: string): Promise<{ thread: ChatThread; messages: ThreadMessage[] } | null> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads/${threadId}`);
  if (!response.ok) {
    if (response.status === 404) return null;
    throw new Error(`Failed to fetch thread: ${response.status}`);
  }
  const data: ServerThreadDetail = await response.json();
  return {
    thread: serverDetailToClient(data),
    messages: prepareMessagesForDisplay(data.messages || []),
  };
}

/**
 * Create a new thread atomically with initial messages
 * The server generates the thread ID to avoid conflicts
 * Idempotent if called through threadCreationTracker
 */
export async function createThread(
  messages: ThreadMessage[],
  title: string,
  scope?: QueryScope | null,
  aiSettings?: AISettings | null
): Promise<ChatThread | null> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages, title, scope, aiSettings }),
  });

  if (!response.ok) {
    throw new Error(`Failed to create thread: ${response.status}`);
  }

  const data = await response.json();
  return {
    id: data.thread_id,
    title: data.title || title,
    createdAt: data.created_at ? new Date(data.created_at).getTime() : Date.now(),
    updatedAt: data.updated_at ? new Date(data.updated_at).getTime() : Date.now(),
    messageCount: data.message_count || messages.length,
    scope: data.scope || null,
    aiSettings: data.aiSettings || null,
  };
}

/**
 * Save messages to an existing thread
 * Idempotent - saving the same messages multiple times is safe
 */
export async function saveMessages(
  threadId: string,
  messages: ThreadMessage[],
  title?: string,
  scope?: QueryScope | null,
  aiSettings?: AISettings | null
): Promise<boolean> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads/${threadId}/messages`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages, title, scope, aiSettings }),
  });
  return response.ok;
}

/**
 * Update thread scope and AI settings
 * Called when the user changes settings mid-conversation
 */
export async function updateThreadSettings(
  threadId: string,
  scope?: QueryScope | null,
  aiSettings?: AISettings | null
): Promise<boolean> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads/${threadId}/settings`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, aiSettings }),
  });
  return response.ok;
}

/**
 * Delete a thread
 * Idempotent - deleting non-existent thread returns success
 */
export async function deleteThread(threadId: string): Promise<boolean> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/threads/${threadId}`, {
    method: "DELETE",
  });
  return response.ok || response.status === 404;
}

// ============================================================================
// Message Transformation
// ============================================================================

/**
 * Prepare messages for display by reconstructing toolCalls where needed.
 *
 * CRITICAL FOR RICH UI: This function enables persisted threads to show the same
 * rich UI (video cards, formatted answers, sources) that they showed during the
 * original conversation.
 *
 * ## Why This Is Needed
 *
 * CopilotKit's `useRenderToolCall` hook matches tool calls by their `function.name`.
 * When a thread is loaded from the server, assistant messages may have:
 *   - Empty content (the LLM doesn't return text when using a tool)
 *   - No `toolCalls` array (the server didn't persist it correctly)
 *
 * Without `toolCalls`, CopilotKit has nothing to render and shows a blank message.
 *
 * ## How It Works
 *
 * 1. Build a map of tool result messages (role: "tool") by their `toolCallId`
 * 2. Parse each tool result's content as JSON to analyze its structure
 * 3. For each assistant message without `toolCalls`:
 *    - Find any following tool result messages that belong to it
 *    - Infer the tool name from the result's JSON structure
 *    - Reconstruct the `toolCalls` array
 *
 * ## Tool Name Matching
 *
 * The inferred tool name MUST match exactly what's registered in useRenderToolCall.
 * Our tools use snake_case: "query_library", "search_videos", etc.
 *
 * @example
 * // Server returns these messages:
 * [
 *   { role: "assistant", content: "" },  // No toolCalls!
 *   { role: "tool", toolCallId: "call_123", content: '{"answer":"...","videoCards":[]}' }
 * ]
 *
 * // This function transforms them to:
 * [
 *   { role: "assistant", content: "", toolCalls: [{ id: "call_123", function: { name: "query_library" } }] },
 *   { role: "tool", toolCallId: "call_123", content: '{"answer":"...","videoCards":[]}' }
 * ]
 *
 * @see useBackendToolRenderers.tsx - where useRenderToolCall registers the renderers
 * @see globals.css - CSS that hides duplicate text content
 */
export function prepareMessagesForDisplay(messages: ThreadMessage[]): ThreadMessage[] {
  // Build map of tool results with parsed content
  const toolResults = new Map<string, { message: ThreadMessage; parsedContent: unknown | null }>();
  for (const msg of messages) {
    if (msg.role === 'tool' && msg.toolCallId) {
      let parsedContent: unknown | null = null;
      if (msg.content) {
        try {
          parsedContent = JSON.parse(msg.content);
        } catch {
          // Not JSON, keep as string - will default to query_library
        }
      }
      toolResults.set(msg.toolCallId, { message: msg, parsedContent });
    }
  }

  // Track tool calls per assistant message
  // An assistant message "owns" all tool messages that come after it until the next assistant
  const assistantToolCalls = new Map<number, string[]>();
  let currentAssistantIdx = -1;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role === 'assistant') {
      currentAssistantIdx = i;
      assistantToolCalls.set(i, []);
    } else if (msg.role === 'tool' && msg.toolCallId && currentAssistantIdx >= 0) {
      assistantToolCalls.get(currentAssistantIdx)?.push(msg.toolCallId);
    }
  }

  /**
   * Infer tool name from the JSON structure of the tool result.
   *
   * CRITICAL: The returned name MUST match the tool name registered in useRenderToolCall.
   * Use snake_case (e.g., "query_library") NOT camelCase (e.g., "queryLibrary").
   *
   * Detection logic is based on unique fields in each tool's response:
   * - query_library: has both "answer" AND "videoCards"
   * - search_videos: has "videos" but NOT "answer"
   * - search_segments: has "segments"
   * - get_video_summary: has "summary" but NOT "answer"
   * - get_library_coverage: has "coverage"
   * - get_topics_for_channel: has "topics"
   */
  const inferToolName = (parsedContent: unknown): string => {
    if (!parsedContent || typeof parsedContent !== 'object') return 'query_library';
    const obj = parsedContent as Record<string, unknown>;

    // query_library returns: answer, videoCards, evidence, followups
    if ('answer' in obj && 'videoCards' in obj) return 'query_library';
    // search_videos returns: videos
    if ('videos' in obj && !('answer' in obj)) return 'search_videos';
    // search_segments returns: segments
    if ('segments' in obj) return 'search_segments';
    // get_video_summary returns: summary
    if ('summary' in obj && !('answer' in obj)) return 'get_video_summary';
    // get_library_coverage returns: coverage
    if ('coverage' in obj) return 'get_library_coverage';
    // get_topics_for_channel returns: topics
    if ('topics' in obj) return 'get_topics_for_channel';

    return 'query_library'; // Default fallback
  };

  // Transform messages
  return messages.map((msg, idx) => {
    // Keep non-assistant messages as-is
    if (msg.role !== 'assistant') return msg;

    // If assistant already has toolCalls, keep it
    if (msg.toolCalls && msg.toolCalls.length > 0) return msg;

    // Check if this assistant has associated tool calls
    const toolCallIds = assistantToolCalls.get(idx) || [];
    if (toolCallIds.length === 0) return msg;

    // Check if all tool calls have results
    const hasAllResults = toolCallIds.every((id) => toolResults.has(id));
    if (!hasAllResults) {
      // Incomplete - return placeholder
      return {
        ...msg,
        id: `${msg.id}-incomplete`,
        content: '⚠️ The previous response was interrupted. Please try sending your message again.',
      };
    }

    // Reconstruct toolCalls from results
    const reconstructedToolCalls = toolCallIds.map((id) => {
      const result = toolResults.get(id);
      const toolName = result?.parsedContent
        ? inferToolName(result.parsedContent)
        : 'query_library';

      return {
        id,
        type: 'function' as const,
        function: {
          name: toolName,
          arguments: '{}',
        },
      };
    });

    return { ...msg, toolCalls: reconstructedToolCalls };
  });
}

/**
 * Generate a clean title from user message content
 */
export function generateTitle(content: string): string {
  const maxLength = 50;
  const cleaned = content.trim().replace(/\s+/g, ' ');

  if (!cleaned) return 'New Chat';

  const capitalized = cleaned.charAt(0).toUpperCase() + cleaned.slice(1);

  if (capitalized.length <= maxLength) return capitalized;

  const truncated = capitalized.substring(0, maxLength);
  const lastSpace = truncated.lastIndexOf(' ');

  if (lastSpace > 20) {
    return truncated.substring(0, lastSpace) + '…';
  }

  return truncated.substring(0, maxLength - 1) + '…';
}

// ============================================================================
// Message Hash for Change Detection
// ============================================================================

/**
 * Compute a hash of messages for change detection.
 * This allows idempotent saves - we only save when content actually changes.
 */
export function computeMessageHash(messages: ThreadMessage[]): string {
  return messages
    .map(
      (m) =>
        `${m.id}:${m.role}:${typeof m.content === 'string' ? m.content.length : 0}:${m.toolCallId || ''}`
    )
    .join('|');
}

/**
 * Check if messages have changed compared to a previous hash
 */
export function messagesChanged(
  currentMessages: ThreadMessage[],
  previousHash: string,
  previousCount: number
): boolean {
  if (currentMessages.length !== previousCount) return true;
  const currentHash = computeMessageHash(currentMessages);
  return currentHash !== previousHash;
}
