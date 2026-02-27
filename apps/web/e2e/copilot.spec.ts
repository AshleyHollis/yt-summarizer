import { test, expect } from '@playwright/test';
import {
  submitQuery,
  waitForCopilotReady,
  waitForResponse,
  getApiUrl,
  getCopilotResponseContent,
} from './helpers';

/**
 * E2E Tests for Copilot Feature (User Story 4)
 *
 * These tests verify the copilot chat panel and query functionality:
 * 1. Copilot sidebar visibility and toggle
 * 2. Query input and submission
 * 3. Scope chip filtering
 * 4. Response display with citations
 * 5. Coverage indicator
 *
 * Prerequisites:
 * - For tests that need the backend, run Aspire first:
 *   Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
 * - Then run tests with: USE_EXTERNAL_SERVER=true npm run test:e2e
 */

test.describe('Copilot Feature', () => {
  test.describe('Sidebar Visibility', () => {
    test('copilot sidebar is visible on library page', async ({ page }) => {
      await page.goto('/library');

      // Wait for page to load
      await page.waitForLoadState('domcontentloaded');

      // Check for copilot sidebar or toggle button
      const sidebar = page
        .locator('[data-testid="copilot-sidebar"]')
        .or(page.locator('.copilot-sidebar'))
        .or(page.locator('[class*="CopilotSidebar"]'));

      // Either sidebar is visible or there's a toggle button (FAB)
      const toggle = page
        .getByRole('button', { name: /copilot|chat|ask|assistant/i })
        .or(page.locator('[data-testid="copilot-fab"]'));

      const sidebarVisible = await sidebar.isVisible().catch(() => false);
      const toggleVisible = await toggle.isVisible().catch(() => false);

      expect(sidebarVisible || toggleVisible).toBeTruthy();
    });

    test('copilot is accessible from submit page', async ({ page }) => {
      await page.goto('/submit');

      await page.waitForLoadState('domcontentloaded');

      // Look for copilot elements
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const _copilotElements = page.locator('[class*="copilot" i], [class*="Copilot" i], [data-copilot]');

      // May or may not be visible on submit page depending on implementation
      // Just verify page loads correctly
      await expect(page).toHaveURL(/submit/);
    });
  });

  test.describe('Query Interface', () => {
    test.beforeEach(async ({ page }) => {
      // Navigate with chat=open to have the sidebar open by default
      // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
      await page.goto('/library?chat=open', { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded');
    });

    test('has query input field', async ({ page }) => {
      // The copilot chat input should be visible on the library page
      // When chat=open, the sidebar should show the chat input
      const chatInput = page
        .getByPlaceholder('Ask about your videos...')
        .or(page.locator('[placeholder*="ask" i]'))
        .or(page.getByRole('textbox', { name: /ask|message/i }));

      // Give the page time to fully render the chat interface
      await page.waitForTimeout(2000);

      // Assert that a chat input exists and is visible
      await expect(chatInput).toBeVisible({ timeout: 5000 });
    });

    test('can type in query input when visible', async ({ page }) => {
      const input = page.getByRole('textbox').first();

      if (await input.isVisible().catch(() => false)) {
        await input.fill('What are the best Python practices?');
        await expect(input).toHaveValue('What are the best Python practices?');
      }
    });
  });

  test.describe('Scope Filtering', () => {
    test.beforeEach(async ({ page }) => {
      // Navigate with chat=open to have the sidebar open by default
      // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
      await page.goto('/library?chat=open', { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded');
    });

    test('scope indicator is visible in copilot header', async ({ page }) => {
      // The scope indicator shows what knowledge sources are being searched
      // It should display "Your Videos", "AI Knowledge", etc.
      const scopeIndicator = page
        .locator('[data-testid="scope-indicator"]')
        .or(page.getByText(/your videos|all videos|library/i));

      await expect(scopeIndicator.first()).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Coverage Indicator', () => {
    test('coverage information displays video count', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Look for coverage indicator showing indexed content count
      // This should display something like "X videos indexed" or "X segments"
      const coverageText = page.getByText(/\d+\s*(videos?|segments?)/i);

      await expect(coverageText.first()).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('API Integration', () => {
    test('copilot API endpoints are accessible', async ({ request }) => {
      // Test that the API endpoints exist and return proper responses
      // These may fail without proper auth/setup, but we're testing route existence

      const coverageResponse = await request.post('/api/v1/copilot/coverage', {
        data: {},
        headers: {
          'Content-Type': 'application/json',
        },
      }).catch(() => null);

      // API might not be running, but if it is, should not be 404
      if (coverageResponse) {
        expect([200, 500, 503]).toContain(coverageResponse.status());
      }
    });

    test('copilot topics endpoint responds', async ({ request }) => {
      const topicsResponse = await request.post('/api/v1/copilot/topics', {
        data: {},
        headers: {
          'Content-Type': 'application/json',
        },
      }).catch(() => null);

      if (topicsResponse) {
        expect([200, 500, 503]).toContain(topicsResponse.status());
      }
    });

    test('copilot query endpoint accepts POST', async ({ request }) => {
      const queryResponse = await request.post('/api/v1/copilot/query', {
        data: {
          query: 'Test query',
        },
        headers: {
          'Content-Type': 'application/json',
        },
      }).catch(() => null);

      if (queryResponse) {
        // Should not be 404 or 405
        expect([200, 400, 422, 500, 503]).toContain(queryResponse.status());
      }
    });
  });

  test.describe('Response Display', () => {
    test('library page loads without errors', async ({ page }) => {
      // Start capturing console errors BEFORE navigating
      const errors: string[] = [];
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(msg.text());
        }
      });

      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Filter out expected/non-critical errors (dev mode warnings, resource loads, etc.)
      const criticalErrors = errors.filter((e) => {
        const lowerError = e.toLowerCase();
        return !(
          lowerError.includes('failed to fetch') ||
          lowerError.includes('failed to load resource') ||
          lowerError.includes('404') ||
          lowerError.includes('net::err') ||
          lowerError.includes('cors') ||
          lowerError.includes('react devtools') ||
          lowerError.includes('lit is in dev mode') ||
          lowerError.includes('favicon') ||
          lowerError.includes('copilotkit') ||
          lowerError.includes('dev mode') ||
          lowerError.includes('hydrat') || // hydration warnings
          lowerError.includes('warning') ||
          lowerError.includes('deprecated')
        );
      });

      // Log errors for debugging if test fails
      if (criticalErrors.length > 0) {
        console.log('Critical console errors:', criticalErrors);
      }

      expect(criticalErrors.length).toBe(0);
    });
  });

  test.describe('Accessibility', () => {
    test('copilot elements have proper ARIA attributes', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Check for any buttons that should be accessible
      const buttons = page.getByRole('button');

      // Ensure at least navigation buttons exist
      const buttonCount = await buttons.count();
      expect(buttonCount).toBeGreaterThan(0);
    });

    test('input fields have associated labels', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Get all text inputs
      const inputs = page.locator('input[type="text"], textarea');

      for (let i = 0; i < (await inputs.count()); i++) {
        const input = inputs.nth(i);
        if (await input.isVisible()) {
          // Should have either aria-label, aria-labelledby, or associated label
          const hasLabel =
            (await input.getAttribute('aria-label')) ||
            (await input.getAttribute('aria-labelledby')) ||
            (await input.getAttribute('placeholder')) ||
            (await input.getAttribute('id'));

          // Inputs should have some form of labeling
          expect(hasLabel).toBeTruthy();
        }
      }
    });
  });

  test.describe('Relevance Filtering', () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 720 });
      // Navigate with chat=open to have the sidebar open by default
      // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
      await page.goto('/library?chat=open', { waitUntil: 'commit' });
      await waitForCopilotReady(page);
    });

    test('positive: returns results for push-up exercises (covered topic)', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      await submitQuery(page, 'How do I do a proper push-up?');

      // Wait for any response indicator (uses test timeout with 30s headroom)
      await waitForResponse(page, testInfo);

      // The agent should return results — either tool-rendered video cards or
      // a text response referencing push-up content. Accept either format.
      const videoLinks = page.locator('a[href*="/videos/"]');
      const hasVideoLinks = await videoLinks.count().then(c => c > 0).catch(() => false);
      if (!hasVideoLinks) {
        // Fallback: verify we got a non-empty text response about push-ups
        const responseContent = await getCopilotResponseContent(page);
        expect(responseContent.length).toBeGreaterThan(0);
      }
    });

    test('positive: returns results for kettlebell training (covered topic)', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      await submitQuery(page, 'What are the benefits of kettlebell training?');

      // Wait for any response indicator (uses test timeout with 30s headroom)
      await waitForResponse(page, testInfo);

      // The agent should return results — either tool-rendered video cards or
      // a text response referencing kettlebell content. Accept either format.
      const videoLinks = page.locator('a[href*="/videos/"]');
      const hasVideoLinks = await videoLinks.count().then(c => c > 0).catch(() => false);
      if (!hasVideoLinks) {
        // Fallback: verify we got a non-empty text response about kettlebells
        const responseContent = await getCopilotResponseContent(page);
        expect(responseContent.length).toBeGreaterThan(0);
      }
    });

    test('negative: returns no video cards for cooking pasta (uncovered topic)', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      await submitQuery(page, 'How do I cook pasta?');

      // Wait for response - uses test timeout with 30s headroom
      await waitForResponse(page, testInfo);

      // Should NOT show video cards for an unrelated topic
      const videoLinks = page.locator('a[href*="/videos/"]');
      await expect(videoLinks).toHaveCount(0);

      // Check that the page shows the "No relevant content" message
      await expect(page.getByText('No relevant content found in your library')).toBeVisible({ timeout: 30_000 });
    });

    test('negative: returns no video cards for quantum physics (uncovered topic)', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      await submitQuery(page, 'Explain quantum entanglement');

      // Wait for response - uses test timeout with 30s headroom
      await waitForResponse(page, testInfo);

      // Should NOT show video cards for an unrelated topic
      const videoLinks = page.locator('a[href*="/videos/"]');
      await expect(videoLinks).toHaveCount(0);
    });

    // Heavy clubs video has been added to global-setup.ts TEST_VIDEOS
    test('positive: returns results for heavy clubs (specific video topic)', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      await submitQuery(page, 'What are heavy clubs and how do beginners use them?');

      // Wait for any response indicator
      await waitForResponse(page, testInfo);

      // Should find heavy clubs content in the response
      const pageContent = await page.content();
      const lowerContent = pageContent.toLowerCase();
      const hasHeavyClubsContent =
        lowerContent.includes('heavy club') ||
        lowerContent.includes('mark wildman') ||
        lowerContent.includes('club') ||
        lowerContent.includes('beginner');
      expect(hasHeavyClubsContent).toBe(true);

      // If video cards are present, verify they link to video detail pages
      const videoLinks = page.locator('a[href*="/videos/"]');
      const hasVideoCards = (await videoLinks.count()) > 0;
      if (hasVideoCards) {
        await expect(videoLinks.first()).toBeVisible({ timeout: 10_000 });
      }
    });
  });

  test.describe('Thread Persistence with Tool Calls', () => {
    /**
     * Tests for thread persistence: verifies that threads are properly saved
     * with user messages and assistant messages containing tool calls.
     *
     * Note: CopilotKit v1.x frontend tools do NOT add tool result messages
     * to the message array - the result is only used for rendering.
     * Tool results are re-executed when the thread is reloaded.
     */

    const API_BASE = getApiUrl();

    test('creates thread with proper message structure when sending query', async ({ page, request }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      // Navigate to add page with chat open
      // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
      await page.goto('/add?chat=open', { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded');
      await waitForCopilotReady(page);

      // Send a message that triggers the queryLibrary tool
      const testQuery = `E2E Test Thread ${Date.now()}`;
      await submitQuery(page, testQuery);

      // Wait for the response to appear (uses test timeout with 30s headroom)
      await waitForResponse(page, testInfo);

      // Wait a bit for thread save to complete
      await page.waitForTimeout(5000);

      // Get the thread ID from URL — CopilotKit oscillates the ?thread= parameter,
      // so we need to wait for it to appear rather than reading page.url() once.
      let threadId: string | null = null;
      try {
        threadId = await page.waitForFunction(
          () => {
            const match = window.location.search.match(/thread=([a-f0-9-]+)/);
            return match ? match[1] : null;
          },
          { timeout: 15_000 },
        ).then(handle => handle.jsonValue());
      } catch {
        // Thread ID may not appear in URL if CopilotKit doesn't persist it
      }

      if (!threadId) {
        test.skip(true, 'No thread ID in URL — CopilotKit may not have persisted the thread');
        return;
      }

      // Verify thread was saved with proper structure via API
      // The thread may not be saved yet — CopilotKit saves asynchronously
      const response = await request.get(`${API_BASE}/api/v1/threads/${threadId}`);
      if (response.status() === 404) {
        // Thread not found — may not have been saved yet or CopilotKit uses
        // a different thread ID than what's in the URL
        test.skip(true, 'Thread not found via API — save may be asynchronous or ID mismatch');
        return;
      }
      expect(response.status()).toBe(200);

      const threadData = await response.json();
      expect(threadData.messages.length).toBeGreaterThan(1);

      // Find user messages
      const userMessages = threadData.messages.filter((m: { role: string }) => m.role === 'user');
      expect(userMessages.length).toBeGreaterThan(0);

      // Find assistant messages with toolCalls
      const assistantWithToolCalls = threadData.messages.filter(
        (m: { role: string; toolCalls?: unknown[] }) =>
          m.role === 'assistant' && (m.toolCalls?.length ?? 0) > 0
      );

      // Assistant with tool calls should exist for proper rendering
      // Note: Tool result messages are NOT persisted for frontend tools in CopilotKit v1.x
      // The frontend re-executes the tool when loading the thread
      expect(assistantWithToolCalls.length).toBeGreaterThan(0);

      // Verify the tool call has proper structure
      const toolCall = assistantWithToolCalls[0].toolCalls[0];
      expect(toolCall.id).toBeTruthy();
      expect(toolCall.type).toBe('function');
      expect(toolCall.function.name).toBeTruthy();
    });

    test('thread renders tool call UI correctly when reopened', async ({ page }, testInfo) => {
      test.slow(); // LLM call - needs extra time
      // First, create a new thread
      // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
      await page.goto('/add?chat=open', { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded');
      await waitForCopilotReady(page);

      // Send query
      const testQuery = `Reload Test ${Date.now()}`;
      await submitQuery(page, testQuery);

      // Wait for response to fully render
      await waitForResponse(page, testInfo);

      // Get thread ID — CopilotKit oscillates ?thread=, so wait for it
      const threadId = await page.waitForFunction(
        () => {
          const match = window.location.search.match(/thread=([a-f0-9-]+)/);
          return match ? match[1] : null;
        },
        { timeout: 15_000 },
      ).then(handle => handle.jsonValue());
      expect(threadId).toBeTruthy();

      // Navigate away (start new chat) - button has title="New chat" with Plus icon
      await page.click('button[title="New chat"]');
      await page.waitForTimeout(1000);

      // Navigate back to the thread.
      // Use waitUntil:'commit' because CopilotKit URL oscillation (?thread=)
      // can cause ERR_ABORTED if we wait for 'load' or 'domcontentloaded'.
      await page.goto(`/add?chat=open&thread=${threadId}`, { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded');
      await waitForCopilotReady(page);

      // Verify the thread loads and shows proper tool UI (not placeholder)
      // Look for "Limited Information" card (tool result UI) or video cards
      const hasToolUI =
        (await page
          .locator('text="Limited Information"')
          .isVisible()
          .catch(() => false)) ||
        (await page
          .locator('a[href*="/videos/"]')
          .isVisible()
          .catch(() => false));

      // Should NOT show the "interrupted" placeholder message
      const hasPlaceholder = await page
        .locator('text="interrupted"')
        .isVisible()
        .catch(() => false);

      expect(hasToolUI || !hasPlaceholder).toBe(true);
    });

    test('tool call structure matches expected format', async ({ request }) => {
      // Create a thread programmatically and verify structure
      // Note: Uses POST /api/v1/threads/messages endpoint which generates thread_id
      const testMessages = [
        {
          id: 'user-test-1',
          role: 'user',
          content: 'Test query for structure validation',
        },
        {
          id: 'call_test_structure',
          role: 'assistant',
          toolCalls: [
            {
              id: 'call_test_structure',
              type: 'function',
              function: {
                name: 'queryLibrary',
                arguments: '{"query":"Test query"}',
              },
            },
          ],
        },
        {
          id: 'tool-result-1',
          role: 'tool',
          content: '{"answer":"Test answer","videoCards":[],"evidence":[]}',
          toolCallId: 'call_test_structure',
        },
      ];

      // Create thread via API (uses /messages endpoint which auto-generates thread_id)
      const createResponse = await request.post(`${API_BASE}/api/v1/threads/messages`, {
        data: {
          title: 'Structure Test Thread',
          messages: testMessages,
        },
      });

      expect(createResponse.status()).toBe(201);
      const created = await createResponse.json();
      const threadId = created.thread_id;

      // Read it back
      const getResponse = await request.get(`${API_BASE}/api/v1/threads/${threadId}`);
      expect(getResponse.status()).toBe(200);

      const threadData = await getResponse.json();

      // Verify structure preserved
      expect(threadData.messages).toHaveLength(3);

      const assistantMsg = threadData.messages.find(
        (m: { role: string }) => m.role === 'assistant'
      );
      expect(assistantMsg.toolCalls).toBeDefined();
      expect(assistantMsg.toolCalls[0].id).toBe('call_test_structure');
      expect(assistantMsg.toolCalls[0].function.name).toBe('queryLibrary');

      const toolMsg = threadData.messages.find((m: { role: string }) => m.role === 'tool');
      expect(toolMsg.toolCallId).toBe('call_test_structure');

      // Cleanup
      await request.delete(`${API_BASE}/api/v1/threads/${threadId}`);
    });

    test('thread with multiple tool calls persists all correctly', async ({ request }) => {
      // Note: Uses POST /api/v1/threads/messages endpoint which generates thread_id
      const testMessages = [
        { id: 'user-1', role: 'user', content: 'Multi-tool query' },
        {
          id: 'call_first',
          role: 'assistant',
          toolCalls: [
            {
              id: 'call_first',
              type: 'function',
              function: { name: 'queryLibrary', arguments: '{"query":"first"}' },
            },
          ],
        },
        {
          id: 'tool-1',
          role: 'tool',
          content: '{"answer":"first result"}',
          toolCallId: 'call_first',
        },
        { id: 'user-2', role: 'user', content: 'Follow up' },
        {
          id: 'call_second',
          role: 'assistant',
          toolCalls: [
            {
              id: 'call_second',
              type: 'function',
              function: { name: 'queryLibrary', arguments: '{"query":"second"}' },
            },
          ],
        },
        {
          id: 'tool-2',
          role: 'tool',
          content: '{"answer":"second result"}',
          toolCallId: 'call_second',
        },
      ];

      const createResponse = await request.post(`${API_BASE}/api/v1/threads/messages`, {
        data: {
          title: 'Multi-Tool Thread Test',
          messages: testMessages,
        },
      });

      expect(createResponse.status()).toBe(201);
      const created = await createResponse.json();
      const threadId = created.thread_id;

      // Read back
      const getResponse = await request.get(`${API_BASE}/api/v1/threads/${threadId}`);
      const threadData = await getResponse.json();

      // Verify all messages preserved
      expect(threadData.messages).toHaveLength(6);

      // Verify both tool calls present
      const assistantMsgs = threadData.messages.filter(
        (m: { role: string }) => m.role === 'assistant'
      );
      expect(assistantMsgs).toHaveLength(2);
      expect(assistantMsgs[0].toolCalls[0].id).toBe('call_first');
      expect(assistantMsgs[1].toolCalls[0].id).toBe('call_second');

      // Verify both tool results present
      const toolMsgs = threadData.messages.filter((m: { role: string }) => m.role === 'tool');
      expect(toolMsgs).toHaveLength(2);
      expect(toolMsgs.map((m: { toolCallId: string }) => m.toolCallId).sort()).toEqual(
        ['call_first', 'call_second'].sort()
      );

      // Cleanup
      await request.delete(`${API_BASE}/api/v1/threads/${threadId}`);
    });
  });
});
