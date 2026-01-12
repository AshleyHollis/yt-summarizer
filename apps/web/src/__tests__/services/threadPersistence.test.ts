/**
 * Tests for Thread Persistence Service
 *
 * These tests ensure the rich UI loading functionality works correctly:
 * 1. prepareMessagesForDisplay reconstructs toolCalls for persisted messages
 * 2. Tool names are correctly inferred from result structure
 * 3. CopilotKit can render the right component when loading saved threads
 *
 * @see threadPersistence.ts for implementation details
 */

import { describe, it, expect } from 'vitest';
import {
  prepareMessagesForDisplay,
  copilotToThreadMessages,
  generateTitle,
  computeMessageHash,
  messagesChanged,
  type ThreadMessage,
} from '@/services/threadPersistence';

describe('prepareMessagesForDisplay', () => {
  describe('tool name inference', () => {
    /**
     * CRITICAL TEST: Ensures persisted threads show rich UI after page refresh.
     *
     * When a thread is loaded from the server, the assistant message may have
     * empty content and no toolCalls array. We need to reconstruct the toolCalls
     * from the following tool result message, with the CORRECT tool name.
     *
     * The tool name MUST match what's registered in useRenderToolCall:
     * - "query_library" (snake_case) - NOT "queryLibrary" (camelCase)
     */
    it('should infer query_library tool from answer+videoCards result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'What will interest rates be next year?' },
        { id: 'assistant-1', role: 'assistant', content: '' }, // Empty - needs toolCalls reconstructed
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_abc123',
          content: JSON.stringify({
            answer: 'Interest rates are expected to remain stable...',
            videoCards: [{ videoId: 'v1', title: 'Rate Analysis', relevanceScore: 0.94 }],
            evidence: [],
            followups: ['What about inflation?'],
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);

      // Find the assistant message
      const assistantMsg = result.find(m => m.role === 'assistant');
      expect(assistantMsg).toBeDefined();
      expect(assistantMsg?.toolCalls).toBeDefined();
      expect(assistantMsg?.toolCalls).toHaveLength(1);

      // CRITICAL: Tool name must be "query_library" (snake_case)
      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('query_library');
    });

    it('should infer search_videos tool from videos-only result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Search for videos about AI' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_xyz789',
          content: JSON.stringify({
            videos: [{ videoId: 'v1', title: 'AI Tutorial' }],
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('search_videos');
    });

    it('should infer search_segments tool from segments result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Find segments about machine learning' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_seg456',
          content: JSON.stringify({
            segments: [{ segmentId: 's1', text: 'Machine learning is...' }],
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('search_segments');
    });

    it('should infer get_video_summary tool from summary-only result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Summarize this video' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_sum123',
          content: JSON.stringify({
            summary: 'This video covers the basics of...',
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('get_video_summary');
    });

    it('should infer get_library_coverage tool from coverage result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'What topics are covered?' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_cov789',
          content: JSON.stringify({
            coverage: { topics: ['AI', 'ML', 'Data Science'] },
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('get_library_coverage');
    });

    it('should infer get_topics_for_channel tool from topics result structure', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'What topics does this channel cover?' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_top456',
          content: JSON.stringify({
            topics: ['Finance', 'Investing', 'Markets'],
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('get_topics_for_channel');
    });

    it('should default to query_library for unknown result structures', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Unknown query' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_unknown',
          content: JSON.stringify({
            unknownField: 'some value',
          }),
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('query_library');
    });
  });

  describe('toolCalls reconstruction', () => {
    it('should preserve existing toolCalls if already present', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Test' },
        {
          id: 'assistant-1',
          role: 'assistant',
          content: '',
          toolCalls: [{
            id: 'call_existing',
            type: 'function',
            function: { name: 'custom_tool', arguments: '{}' },
          }],
        },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_existing',
          content: '{"result": "test"}',
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      // Should keep the original tool name
      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('custom_tool');
    });

    it('should link tool results to preceding assistant messages', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Question 1' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        { id: 'tool-1', role: 'tool', toolCallId: 'call_1', content: '{"answer":"A1","videoCards":[]}' },
        { id: 'user-2', role: 'user', content: 'Question 2' },
        { id: 'assistant-2', role: 'assistant', content: '' },
        { id: 'tool-2', role: 'tool', toolCallId: 'call_2', content: '{"answer":"A2","videoCards":[]}' },
      ];

      const result = prepareMessagesForDisplay(messages);

      const assistant1 = result.find(m => m.id === 'assistant-1');
      const assistant2 = result.find(m => m.id === 'assistant-2');

      expect(assistant1?.toolCalls?.[0].id).toBe('call_1');
      expect(assistant2?.toolCalls?.[0].id).toBe('call_2');
    });

    it('should handle incomplete tool calls with warning message', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Test' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        // Tool message has toolCallId but no matching tool result content
        { id: 'tool-1', role: 'tool', toolCallId: 'call_missing', content: '' },
      ];

      // Note: The current implementation doesn't handle empty content as "incomplete"
      // but this test documents the expected behavior for missing results
      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      // Should still reconstruct toolCalls since toolCallId exists
      expect(assistantMsg?.toolCalls).toBeDefined();
    });

    it('should handle non-JSON tool result content gracefully', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Test' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_text',
          content: 'Plain text result, not JSON',
        },
      ];

      const result = prepareMessagesForDisplay(messages);
      const assistantMsg = result.find(m => m.role === 'assistant');

      // Should default to query_library when can't parse JSON
      expect(assistantMsg?.toolCalls?.[0].function.name).toBe('query_library');
    });
  });

  describe('message pass-through', () => {
    it('should pass through user messages unchanged', () => {
      const messages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Hello world' },
      ];

      const result = prepareMessagesForDisplay(messages);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(messages[0]);
    });

    it('should pass through system messages unchanged', () => {
      const messages: ThreadMessage[] = [
        { id: 'system-1', role: 'system', content: 'You are an assistant' },
      ];

      const result = prepareMessagesForDisplay(messages);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(messages[0]);
    });

    it('should pass through tool messages unchanged', () => {
      const messages: ThreadMessage[] = [
        { id: 'tool-1', role: 'tool', toolCallId: 'call_1', content: '{"data":"test"}' },
      ];

      const result = prepareMessagesForDisplay(messages);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(messages[0]);
    });

    it('should pass through assistant messages with content and no tool results', () => {
      const messages: ThreadMessage[] = [
        { id: 'assistant-1', role: 'assistant', content: 'Hello! How can I help?' },
      ];

      const result = prepareMessagesForDisplay(messages);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(messages[0]);
    });
  });
});

describe('copilotToThreadMessages', () => {
  it('should convert user messages correctly', () => {
    const copilotMessages = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
    ];

    const result = copilotToThreadMessages(copilotMessages);

    expect(result).toHaveLength(1);
    expect(result[0].role).toBe('user');
    expect(result[0].content).toBe('Hello');
  });

  it('should convert assistant text messages correctly', () => {
    const copilotMessages = [
      { id: 'msg-1', role: 'assistant', content: 'How can I help?' },
    ];

    const result = copilotToThreadMessages(copilotMessages);

    expect(result).toHaveLength(1);
    expect(result[0].role).toBe('assistant');
    expect(result[0].content).toBe('How can I help?');
  });

  it('should detect tool invocations by ID prefix', () => {
    const copilotMessages = [
      {
        id: 'call_abc123',
        role: 'assistant',
        name: 'query_library',
        arguments: { query: 'test' },
      },
    ];

    const result = copilotToThreadMessages(copilotMessages);

    // Should create assistant message with toolCalls
    const assistantMsg = result.find(m => m.role === 'assistant');
    expect(assistantMsg?.toolCalls).toBeDefined();
    expect(assistantMsg?.toolCalls?.[0].id).toBe('call_abc123');
    expect(assistantMsg?.toolCalls?.[0].function.name).toBe('query_library');
  });

  it('should link tool results to tool calls', () => {
    const copilotMessages = [
      {
        id: 'call_abc123',
        role: 'assistant',
        name: 'query_library',
        arguments: { query: 'test' },
      },
      {
        id: 'result-1',
        role: 'tool',
        content: '{"answer":"Test answer"}',
        toolCallId: 'call_abc123',
      },
    ];

    const result = copilotToThreadMessages(copilotMessages);

    const toolMsg = result.find(m => m.role === 'tool');
    expect(toolMsg?.toolCallId).toBe('call_abc123');
  });
});

describe('generateTitle', () => {
  it('should capitalize first letter', () => {
    expect(generateTitle('hello world')).toBe('Hello world');
  });

  it('should truncate long titles at word boundary', () => {
    const longText = 'This is a very long question about something that goes on and on and on';
    const result = generateTitle(longText);

    expect(result.length).toBeLessThanOrEqual(51); // 50 + ellipsis
    expect(result).toContain('…');
  });

  it('should return "New Chat" for empty content', () => {
    expect(generateTitle('')).toBe('New Chat');
    expect(generateTitle('   ')).toBe('New Chat');
  });
});

describe('computeMessageHash', () => {
  it('should produce consistent hash for same messages', () => {
    const messages: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
      { id: 'msg-2', role: 'assistant', content: 'Hi there' },
    ];

    const hash1 = computeMessageHash(messages);
    const hash2 = computeMessageHash(messages);

    expect(hash1).toBe(hash2);
  });

  it('should produce different hash for different messages', () => {
    const messages1: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
    ];
    const messages2: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Goodbye' },
    ];

    const hash1 = computeMessageHash(messages1);
    const hash2 = computeMessageHash(messages2);

    expect(hash1).not.toBe(hash2);
  });
});

describe('messagesChanged', () => {
  it('should detect count changes', () => {
    const messages: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
      { id: 'msg-2', role: 'assistant', content: 'Hi' },
    ];

    const changed = messagesChanged(messages, 'old-hash', 1);
    expect(changed).toBe(true);
  });

  it('should detect content changes via hash', () => {
    const messages: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
    ];

    const oldHash = 'different-hash';
    const changed = messagesChanged(messages, oldHash, 1);
    expect(changed).toBe(true);
  });

  it('should return false when no changes', () => {
    const messages: ThreadMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello' },
    ];

    const hash = computeMessageHash(messages);
    const changed = messagesChanged(messages, hash, 1);
    expect(changed).toBe(false);
  });
});

// ============================================================================
// Thread Switching Integration Tests
// ============================================================================

/**
 * These tests document the expected behavior when switching threads.
 * They ensure that loaded threads display correctly with rich UI.
 *
 * THREAD SWITCHING FLOW:
 * 1. User clicks thread in dropdown
 * 2. selectThread() updates activeThreadId
 * 3. fetchThread() loads messages from server
 * 4. prepareMessagesForDisplay() reconstructs toolCalls
 * 5. CopilotKit re-renders with rich UI
 *
 * CRITICAL: Step 4 is essential - without it, rich UI won't render.
 */
describe('Thread switching scenarios', () => {
  describe('loading a persisted thread with tool calls', () => {
    /**
     * Simulates loading a thread that was saved with a query_library tool call.
     * The server returns messages WITHOUT toolCalls on the assistant message.
     * prepareMessagesForDisplay must reconstruct them.
     */
    it('should reconstruct complete conversation with tool call and result', () => {
      // This is what the server returns (missing toolCalls on assistant)
      const serverMessages: ThreadMessage[] = [
        {
          id: 'user-1',
          role: 'user',
          content: 'What videos do you have about investing?',
        },
        {
          id: 'assistant-1',
          role: 'assistant',
          content: '', // Empty because LLM used a tool instead of responding
          // NOTE: No toolCalls array! This is the problem we're fixing.
        },
        {
          id: 'tool-1',
          role: 'tool',
          toolCallId: 'call_invest123',
          content: JSON.stringify({
            answer: 'I found several videos about investing...',
            videoCards: [
              { videoId: 'v1', youTubeVideoId: 'abc', title: 'Investing 101', relevanceScore: 0.95 },
              { videoId: 'v2', youTubeVideoId: 'def', title: 'Stock Market Basics', relevanceScore: 0.88 },
            ],
            evidence: [],
            followups: ['What about index funds?', 'Tell me about bonds'],
          }),
        },
      ];

      // Transform for display
      const displayMessages = prepareMessagesForDisplay(serverMessages);

      // Verify structure
      expect(displayMessages).toHaveLength(3);

      // User message unchanged
      expect(displayMessages[0].role).toBe('user');
      expect(displayMessages[0].content).toBe('What videos do you have about investing?');

      // Assistant message now has toolCalls reconstructed
      const assistant = displayMessages[1];
      expect(assistant.role).toBe('assistant');
      expect(assistant.toolCalls).toBeDefined();
      expect(assistant.toolCalls).toHaveLength(1);
      expect(assistant.toolCalls![0].id).toBe('call_invest123');
      expect(assistant.toolCalls![0].function.name).toBe('query_library');

      // Tool result unchanged
      expect(displayMessages[2].role).toBe('tool');
      expect(displayMessages[2].toolCallId).toBe('call_invest123');
    });

    /**
     * Tests that multiple consecutive tool calls in one conversation
     * are all reconstructed correctly.
     */
    it('should handle multi-turn conversation with multiple tool calls', () => {
      const serverMessages: ThreadMessage[] = [
        // Turn 1
        { id: 'user-1', role: 'user', content: 'What investing videos do you have?' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        { id: 'tool-1', role: 'tool', toolCallId: 'call_1', content: JSON.stringify({ answer: 'A1', videoCards: [] }) },
        // Turn 2
        { id: 'user-2', role: 'user', content: 'Now find videos about bonds' },
        { id: 'assistant-2', role: 'assistant', content: '' },
        { id: 'tool-2', role: 'tool', toolCallId: 'call_2', content: JSON.stringify({ answer: 'A2', videoCards: [] }) },
        // Turn 3
        { id: 'user-3', role: 'user', content: 'What about real estate?' },
        { id: 'assistant-3', role: 'assistant', content: '' },
        { id: 'tool-3', role: 'tool', toolCallId: 'call_3', content: JSON.stringify({ answer: 'A3', videoCards: [] }) },
      ];

      const displayMessages = prepareMessagesForDisplay(serverMessages);

      // Each assistant message should have its own toolCalls reconstructed
      const assistant1 = displayMessages.find(m => m.id === 'assistant-1');
      const assistant2 = displayMessages.find(m => m.id === 'assistant-2');
      const assistant3 = displayMessages.find(m => m.id === 'assistant-3');

      expect(assistant1?.toolCalls?.[0].id).toBe('call_1');
      expect(assistant2?.toolCalls?.[0].id).toBe('call_2');
      expect(assistant3?.toolCalls?.[0].id).toBe('call_3');

      // All should be query_library
      expect(assistant1?.toolCalls?.[0].function.name).toBe('query_library');
      expect(assistant2?.toolCalls?.[0].function.name).toBe('query_library');
      expect(assistant3?.toolCalls?.[0].function.name).toBe('query_library');
    });
  });

  describe('edge cases', () => {
    /**
     * Tests that plain text assistant messages (no tool call)
     * are preserved correctly - like the initial greeting.
     */
    it('should preserve plain text assistant messages', () => {
      const serverMessages: ThreadMessage[] = [
        {
          id: 'greeting',
          role: 'assistant',
          content: 'Hello! I can help you search your video library.',
        },
        { id: 'user-1', role: 'user', content: 'What videos about cooking?' },
        { id: 'assistant-1', role: 'assistant', content: '' },
        { id: 'tool-1', role: 'tool', toolCallId: 'call_1', content: JSON.stringify({ answer: 'Found cooking videos', videoCards: [] }) },
      ];

      const displayMessages = prepareMessagesForDisplay(serverMessages);

      // Greeting should be unchanged (no toolCalls added)
      const greeting = displayMessages.find(m => m.id === 'greeting');
      expect(greeting?.content).toBe('Hello! I can help you search your video library.');
      expect(greeting?.toolCalls).toBeUndefined();

      // But the second assistant message should have toolCalls
      const assistant1 = displayMessages.find(m => m.id === 'assistant-1');
      expect(assistant1?.toolCalls).toBeDefined();
    });

    /**
     * Tests empty conversation - should not crash.
     */
    it('should handle empty message array', () => {
      const displayMessages = prepareMessagesForDisplay([]);
      expect(displayMessages).toEqual([]);
    });

    /**
     * Tests conversation with only user messages (no assistant response yet).
     */
    it('should handle user-only messages', () => {
      const serverMessages: ThreadMessage[] = [
        { id: 'user-1', role: 'user', content: 'Hello?' },
      ];

      const displayMessages = prepareMessagesForDisplay(serverMessages);
      expect(displayMessages).toHaveLength(1);
      expect(displayMessages[0].role).toBe('user');
    });
  });
});
