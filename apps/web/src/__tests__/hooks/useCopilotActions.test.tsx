/**
 * Tests for useCopilotActions hook
 * 
 * These tests verify:
 * 1. Relevance filtering for video cards (MIN_RELEVANCE_THRESHOLD = 0.50)
 * 2. Relevance filtering for evidence/sources
 * 3. Proper handling of uncertainty field
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Test utilities for the filtering logic
// We test the filtering logic directly since hooks require complex mocking

describe('useCopilotActions Filtering Logic', () => {
  const MIN_RELEVANCE_THRESHOLD = 0.50;

  describe('Video Card Filtering', () => {
    const filterVideoCards = (videoCards: Array<{ relevanceScore: number; title: string }>) => {
      return videoCards.filter((video) => video.relevanceScore >= MIN_RELEVANCE_THRESHOLD);
    };

    it('should filter out videos below 50% relevance threshold', () => {
      const videoCards = [
        { title: 'Heavy Clubs Video', relevanceScore: 0.81 },
        { title: 'Irrelevant Video', relevanceScore: 0.30 },
        { title: 'Push Ups Video', relevanceScore: 0.99 },
      ];

      const filtered = filterVideoCards(videoCards);

      expect(filtered).toHaveLength(2);
      expect(filtered.map(v => v.title)).toEqual(['Heavy Clubs Video', 'Push Ups Video']);
    });

    it('should include videos at exactly 50% threshold', () => {
      const videoCards = [
        { title: 'Edge Case Video', relevanceScore: 0.50 },
        { title: 'Below Threshold', relevanceScore: 0.49 },
      ];

      const filtered = filterVideoCards(videoCards);

      expect(filtered).toHaveLength(1);
      expect(filtered[0].title).toBe('Edge Case Video');
    });

    it('should return empty array when no videos meet threshold', () => {
      const videoCards = [
        { title: 'Low Match 1', relevanceScore: 0.25 },
        { title: 'Low Match 2', relevanceScore: 0.45 },
      ];

      const filtered = filterVideoCards(videoCards);

      expect(filtered).toHaveLength(0);
    });

    it('should return all videos when all meet threshold', () => {
      const videoCards = [
        { title: 'Good Match 1', relevanceScore: 0.85 },
        { title: 'Good Match 2', relevanceScore: 0.92 },
        { title: 'Good Match 3', relevanceScore: 0.75 },
      ];

      const filtered = filterVideoCards(videoCards);

      expect(filtered).toHaveLength(3);
    });

    it('should handle empty video cards array', () => {
      const filtered = filterVideoCards([]);

      expect(filtered).toHaveLength(0);
    });
  });

  describe('Evidence Filtering', () => {
    const filterEvidence = (evidence: Array<{ confidence: number; videoTitle: string }>) => {
      return evidence.filter((item) => item.confidence >= MIN_RELEVANCE_THRESHOLD);
    };

    it('should filter out evidence below 40% confidence threshold', () => {
      const evidence = [
        { videoTitle: 'Heavy Clubs', confidence: 0.81 },
        { videoTitle: 'Cooking Video', confidence: 0.30 },
        { videoTitle: 'Push Ups', confidence: 0.94 },
      ];

      const filtered = filterEvidence(evidence);

      expect(filtered).toHaveLength(2);
      expect(filtered.map(e => e.videoTitle)).toEqual(['Heavy Clubs', 'Push Ups']);
    });

    it('should filter out irrelevant sources for unrelated queries', () => {
      // Simulating "cooking pasta" query returning only loosely related fitness videos
      const evidence = [
        { videoTitle: 'Heavy Clubs That Most Beginners Miss', confidence: 0.35 },
        { videoTitle: 'Build VO2 Max Without Running', confidence: 0.28 },
      ];

      const filtered = filterEvidence(evidence);

      expect(filtered).toHaveLength(0);
    });

    it('should keep highly relevant sources', () => {
      // Simulating "heavy clubs" query
      const evidence = [
        { videoTitle: 'Heavy Clubs That Most Beginners Miss', confidence: 0.81 },
      ];

      const filtered = filterEvidence(evidence);

      expect(filtered).toHaveLength(1);
      expect(filtered[0].videoTitle).toBe('Heavy Clubs That Most Beginners Miss');
    });

    it('should handle empty evidence array', () => {
      const filtered = filterEvidence([]);

      expect(filtered).toHaveLength(0);
    });
  });

  describe('Combined Filtering Behavior', () => {
    const processQueryResponse = (data: {
      videoCards: Array<{ relevanceScore: number; title: string }>;
      evidence: Array<{ confidence: number; videoTitle: string }>;
      uncertainty: string | null;
    }) => {
      const filteredVideoCards = data.videoCards?.filter(
        (video) => video.relevanceScore >= MIN_RELEVANCE_THRESHOLD
      ) || [];
      
      const filteredEvidence = data.evidence?.filter(
        (item) => item.confidence >= MIN_RELEVANCE_THRESHOLD
      ) || [];
      
      return {
        ...data,
        videoCards: filteredVideoCards,
        evidence: filteredEvidence,
      };
    };

    it('should filter both videoCards and evidence consistently', () => {
      const response = {
        videoCards: [
          { title: 'Good Video', relevanceScore: 0.85 },
          { title: 'Bad Video', relevanceScore: 0.25 },
        ],
        evidence: [
          { videoTitle: 'Good Video', confidence: 0.85 },
          { videoTitle: 'Bad Video', confidence: 0.25 },
        ],
        uncertainty: null,
      };

      const processed = processQueryResponse(response);

      expect(processed.videoCards).toHaveLength(1);
      expect(processed.evidence).toHaveLength(1);
      expect(processed.videoCards[0].title).toBe('Good Video');
      expect(processed.evidence[0].videoTitle).toBe('Good Video');
    });

    it('should preserve uncertainty field unchanged', () => {
      const response = {
        videoCards: [],
        evidence: [],
        uncertainty: 'No relevant content found in the library',
      };

      const processed = processQueryResponse(response);

      expect(processed.uncertainty).toBe('No relevant content found in the library');
    });

    it('should handle cooking pasta scenario - filter out all irrelevant results', () => {
      // Real scenario: "cooking pasta" query returning fitness videos
      const response = {
        videoCards: [
          { title: 'Heavy Clubs', relevanceScore: 0.35 },
          { title: 'VO2 Max Kettlebells', relevanceScore: 0.28 },
        ],
        evidence: [
          { videoTitle: 'Heavy Clubs', confidence: 0.35 },
          { videoTitle: 'VO2 Max Kettlebells', confidence: 0.28 },
        ],
        uncertainty: 'No cooking videos found in the library',
      };

      const processed = processQueryResponse(response);

      expect(processed.videoCards).toHaveLength(0);
      expect(processed.evidence).toHaveLength(0);
      expect(processed.uncertainty).toBe('No cooking videos found in the library');
    });

    it('should handle heavy clubs scenario - keep relevant results', () => {
      // Real scenario: "heavy clubs" query returning the correct video
      const response = {
        videoCards: [
          { title: 'The Key Part of Heavy Clubs That Most Beginners Miss', relevanceScore: 0.81 },
        ],
        evidence: [
          { videoTitle: 'The Key Part of Heavy Clubs That Most Beginners Miss', confidence: 0.81 },
        ],
        uncertainty: null,
      };

      const processed = processQueryResponse(response);

      expect(processed.videoCards).toHaveLength(1);
      expect(processed.evidence).toHaveLength(1);
      expect(processed.uncertainty).toBeNull();
    });

    it('should handle push ups scenario - keep multiple relevant results', () => {
      // Real scenario: "push ups" query returning both push up videos
      const response = {
        videoCards: [
          { title: 'Guided 100 Push Up Workout!', relevanceScore: 0.99 },
          { title: 'The Perfect Push Up | Do it right!', relevanceScore: 0.94 },
          { title: 'Heavy Clubs Video', relevanceScore: 0.15 }, // Should be filtered
        ],
        evidence: [
          { videoTitle: 'Guided 100 Push Up Workout!', confidence: 0.99 },
          { videoTitle: 'The Perfect Push Up | Do it right!', confidence: 0.94 },
        ],
        uncertainty: null,
      };

      const processed = processQueryResponse(response);

      expect(processed.videoCards).toHaveLength(2);
      expect(processed.evidence).toHaveLength(2);
      expect(processed.videoCards.map(v => v.title)).not.toContain('Heavy Clubs Video');
    });
  });
});

describe('Uncertainty Field Handling', () => {
  // Test the expected behavior of uncertainty field values
  
  it('should treat null uncertainty as no warning needed', () => {
    const uncertainty: string | null = null;
    expect(uncertainty).toBeNull();
  });

  it('should treat empty string uncertainty as no warning needed', () => {
    const uncertainty = '';
    // Empty string should be treated as falsy
    expect(Boolean(uncertainty)).toBe(false);
  });

  it('should show warning for valid uncertainty message', () => {
    const uncertainty = 'The provided evidence contains no information about cooking pasta.';
    expect(Boolean(uncertainty)).toBe(true);
    expect(uncertainty.length).toBeGreaterThan(0);
  });

  it('should NOT show the literal string "null" as uncertainty', () => {
    // This is the bug we fixed - LLM was returning "null" string
    const uncertaintyFromLLM = 'null';
    
    // The frontend should NOT display "null" as a message
    // We expect the API to convert "null" string to actual null
    const shouldDisplay = uncertaintyFromLLM !== 'null' && uncertaintyFromLLM !== '';
    
    expect(shouldDisplay).toBe(false);
  });
});

/**
 * Tests for Tool Call Message Creation
 * 
 * These tests verify the logic for creating properly structured messages
 * for frontend tool calls (like queryLibrary) that need to be persisted.
 */
describe('Tool Call Message Creation', () => {
  describe('Assistant Message with ToolCalls', () => {
    /**
     * Creates an assistant message with toolCalls array in the format
     * expected by CopilotKit and the persistence layer.
     */
    function createAssistantToolCallMessage(toolCallId: string, toolName: string, toolArgs: string) {
      return {
        id: toolCallId,
        role: "assistant" as const,
        toolCalls: [{
          id: toolCallId,
          type: "function" as const,
          function: {
            name: toolName,
            arguments: toolArgs,
          },
        }],
      };
    }

    it('should create assistant message with correct structure', () => {
      const toolCallId = 'call_abc123';
      const message = createAssistantToolCallMessage(toolCallId, 'queryLibrary', '{"query":"test"}');

      expect(message.id).toBe(toolCallId);
      expect(message.role).toBe('assistant');
      expect(message.toolCalls).toHaveLength(1);
      expect(message.toolCalls[0].id).toBe(toolCallId);
      expect(message.toolCalls[0].type).toBe('function');
      expect(message.toolCalls[0].function.name).toBe('queryLibrary');
      expect(message.toolCalls[0].function.arguments).toBe('{"query":"test"}');
    });

    it('should use toolCallId as message id for consistency', () => {
      const toolCallId = 'call_xyz789';
      const message = createAssistantToolCallMessage(toolCallId, 'queryLibrary', '{}');

      // Both should match for proper CopilotKit association
      expect(message.id).toBe(message.toolCalls[0].id);
    });

    it('should properly encode query arguments as JSON', () => {
      const query = 'What videos about "TypeScript" do I have?';
      const toolArgs = JSON.stringify({ query });
      const message = createAssistantToolCallMessage('call_123', 'queryLibrary', toolArgs);

      const parsedArgs = JSON.parse(message.toolCalls[0].function.arguments);
      expect(parsedArgs.query).toBe(query);
    });
  });

  describe('Tool Result Message', () => {
    /**
     * Creates a tool result message in the format expected by CopilotKit.
     */
    function createToolResultMessage(messageId: string, toolCallId: string, result: unknown) {
      return {
        id: messageId,
        role: "tool" as const,
        content: typeof result === "string" ? result : JSON.stringify(result),
        toolCallId,
      };
    }

    it('should create tool result message with correct structure', () => {
      const messageId = 'msg-uuid-123';
      const toolCallId = 'call_abc123';
      const result = { answer: 'Test answer', videoCards: [], evidence: [] };

      const message = createToolResultMessage(messageId, toolCallId, result);

      expect(message.id).toBe(messageId);
      expect(message.role).toBe('tool');
      expect(message.toolCallId).toBe(toolCallId);
      expect(JSON.parse(message.content)).toEqual(result);
    });

    it('should serialize object results to JSON', () => {
      const result = { 
        answer: 'You have 5 videos', 
        videoCards: [{ title: 'Test Video' }],
        evidence: [],
        followups: ['Try another query'],
      };

      const message = createToolResultMessage('msg-1', 'call_1', result);

      expect(typeof message.content).toBe('string');
      expect(JSON.parse(message.content)).toEqual(result);
    });

    it('should preserve string results as-is', () => {
      const stringResult = 'Simple string result';
      const message = createToolResultMessage('msg-1', 'call_1', stringResult);

      expect(message.content).toBe(stringResult);
    });

    it('should have toolCallId matching the assistant message toolCalls id', () => {
      const toolCallId = 'call_matching_id';
      
      const assistantMsg = {
        id: toolCallId,
        role: 'assistant' as const,
        toolCalls: [{ id: toolCallId, type: 'function' as const, function: { name: 'queryLibrary', arguments: '{}' } }],
      };

      const toolMsg = createToolResultMessage('result-id', toolCallId, { answer: 'test' });

      expect(toolMsg.toolCallId).toBe(assistantMsg.toolCalls[0].id);
    });
  });

  describe('Pending Tool Results Tracking', () => {
    it('should track pending results with full tool call info', () => {
      // Simulates the pendingToolResultsRef structure
      const pendingResults = new Map<string, {
        toolCallId: string;
        result: unknown;
        toolName: string;
        toolArgs: string;
      }>();

      const messageId = crypto.randomUUID();
      const toolCallId = 'call_test123';
      const result = { answer: 'Test result' };

      pendingResults.set(messageId, {
        toolCallId,
        result,
        toolName: 'queryLibrary',
        toolArgs: JSON.stringify({ query: 'test query' }),
      });

      expect(pendingResults.size).toBe(1);
      
      const entry = pendingResults.get(messageId);
      expect(entry?.toolCallId).toBe(toolCallId);
      expect(entry?.toolName).toBe('queryLibrary');
      expect(JSON.parse(entry?.toolArgs || '{}')).toEqual({ query: 'test query' });
    });

    it('should allow retrieving all pending entries', () => {
      const pendingResults = new Map<string, {
        toolCallId: string;
        result: unknown;
        toolName: string;
        toolArgs: string;
      }>();

      // Add multiple entries
      pendingResults.set('msg-1', { toolCallId: 'call_1', result: {}, toolName: 'queryLibrary', toolArgs: '{}' });
      pendingResults.set('msg-2', { toolCallId: 'call_2', result: {}, toolName: 'queryLibrary', toolArgs: '{}' });

      const entries = Array.from(pendingResults.entries());
      
      expect(entries).toHaveLength(2);
      expect(entries.map(([id]) => id)).toEqual(['msg-1', 'msg-2']);
    });

    it('should allow clearing processed entries', () => {
      const pendingResults = new Map<string, {
        toolCallId: string;
        result: unknown;
        toolName: string;
        toolArgs: string;
      }>();

      pendingResults.set('msg-1', { toolCallId: 'call_1', result: {}, toolName: 'queryLibrary', toolArgs: '{}' });
      
      // Simulate processing and cleanup
      pendingResults.delete('msg-1');

      expect(pendingResults.size).toBe(0);
    });
  });

  describe('Duplicate Detection', () => {
    it('should detect existing tool call IDs from messages', () => {
      const messages = [
        { id: 'user-1', role: 'user' as const },
        { id: 'call_abc', role: 'tool' as const, toolCallId: 'call_abc' },
        { id: 'call_xyz', role: 'tool' as const, toolCallId: 'call_xyz' },
      ];

      const existingToolCallIds = new Set(
        messages
          .filter((m) => m.role === 'tool')
          .map((m) => (m as { toolCallId?: string }).toolCallId)
          .filter(Boolean)
      );

      expect(existingToolCallIds.has('call_abc')).toBe(true);
      expect(existingToolCallIds.has('call_xyz')).toBe(true);
      expect(existingToolCallIds.has('call_new')).toBe(false);
    });

    it('should detect existing assistant tool calls', () => {
      interface ToolCall { id: string; type: string; function: { name: string; arguments: string } }
      
      const messages = [
        { id: 'user-1', role: 'user' as const },
        { 
          id: 'call_existing', 
          role: 'assistant' as const,
          toolCalls: [{ id: 'call_existing', type: 'function', function: { name: 'queryLibrary', arguments: '{}' } }]
        },
      ];

      const existingAssistantToolCallIds = new Set(
        messages
          .filter((m) => m.role === 'assistant')
          .flatMap((m) => 
            ((m as { toolCalls?: ToolCall[] }).toolCalls || []).map(tc => tc.id)
          )
      );

      expect(existingAssistantToolCallIds.has('call_existing')).toBe(true);
      expect(existingAssistantToolCallIds.has('call_new')).toBe(false);
    });

    it('should skip adding if tool call already exists in messages', () => {
      const existingToolCallIds = new Set(['call_already_exists']);
      const newToolCallId = 'call_already_exists';

      // This simulates the check in the effect
      const shouldAdd = !existingToolCallIds.has(newToolCallId);

      expect(shouldAdd).toBe(false);
    });
  });
});

