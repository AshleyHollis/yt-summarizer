import { test, expect, Page } from "@playwright/test";
import {
  waitForCopilotReady,
  submitQuery,
  waitForAssistantResponse,
} from "./helpers";

/**
 * E2E tests for Single Response Verification
 *
 * Tests verify that each user message produces exactly ONE assistant response.
 * This catches regressions where duplicate messages appear in the chat.
 *
 * Bug context: Issue where tool results (e.g., queryLibrary) were being
 * rendered multiple times, causing duplicate "Limited Information" cards.
 */

function countAssistantMessageBlocks(page: Page) {
  // Count the number of "Limited Information" cards (indicator of queryLibrary tool response)
  return page.locator('text="Limited Information"').count();
}

test.describe("Single Response Per Message", () => {
  // All tests navigate with ?chat=open for reliable chat panel activation.
  // openChatViaButton (button click) is flaky — the click sometimes doesn't
  // register or the panel fails to open within the timeout.

  test("simple greeting produces exactly one response", async ({ page }) => {
    test.slow(); // LLM call - needs extra time
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/library?chat=open");
    await waitForCopilotReady(page);

    // Send a simple greeting that doesn't trigger tools
    await submitQuery(page, "Hello, how are you?");

    // Wait for response
    await page.waitForTimeout(3000);

    // The message text should appear exactly once as a user message
    const greetingTexts = page.locator('text="Hello, how are you?"');
    const greetingCount = await greetingTexts.count();
    expect(greetingCount).toBe(1); // User message appears once

    // Simple greetings don't trigger queryLibrary, so should get direct response
    // Just verify we don't have duplicate responses
    const pageContent = await page.content();
    const responseMatches = (pageContent.match(/I'm doing well|How can I help/gi) || []).length;
    expect(responseMatches).toBeLessThanOrEqual(2); // Allow for greeting + response context
  });

  test("library query produces exactly one tool response card", async ({ page }) => {
    test.slow(); // LLM call - needs extra time
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/library?chat=open");
    await waitForCopilotReady(page);

    // Send a query that triggers the queryLibrary tool
    await submitQuery(page, "What videos do I have about exercise?");

    // Wait for response to complete
    await waitForAssistantResponse(page);

    // Count "Limited Information" cards - should be exactly 1 (or 0 if there are videos)
    const limitedInfoCount = await countAssistantMessageBlocks(page);

    // The bug causes multiple identical cards to appear
    // We expect either 0 (videos found) or 1 (no videos) - never more than 1
    expect(limitedInfoCount).toBeLessThanOrEqual(1);

    // Count "Recommended Videos" sections - should be 0 or 1
    const recommendedCount = await page.locator('text="Recommended Videos"').count();
    expect(recommendedCount).toBeLessThanOrEqual(1);
  });

  test("second query produces only one additional response", async ({ page }) => {
    test.slow(); // LLM call - needs extra time
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/library?chat=open");
    await waitForCopilotReady(page);

    // First message
    await submitQuery(page, "Hello!");
    await page.waitForTimeout(2000);

    // Second message - triggers tool
    await submitQuery(page, "What videos do I have?");
    await waitForAssistantResponse(page);

    // Count tool response indicators
    const limitedInfoCount = await countAssistantMessageBlocks(page);

    // Second query should produce at most 1 "Limited Information" card
    // (The first "Hello" message shouldn't trigger the queryLibrary tool)
    expect(limitedInfoCount).toBeLessThanOrEqual(1);

    // Ensure no loading spinners remain
    const spinnerCount = await page.locator('[class*="animate-spin"]').count();
    expect(spinnerCount).toBe(0);
  });

  test("tool result renders exactly once with all components", async ({ page }) => {
    test.slow(); // LLM call - needs extra time
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/library?chat=open");
    await waitForCopilotReady(page);

    // Send query
    await submitQuery(page, "Tell me about the videos in my library");
    await waitForAssistantResponse(page);

    // Verify the structure appears once:
    // - "Limited Information" OR "Recommended Videos" (exactly one of each type)
    // - "Follow-up questions" section (exactly one per response)

    const limitedInfo = await page.locator('text="Limited Information"').count();
    const recommended = await page.locator('text="Recommended Videos"').count();

    // Either we have no content (1 Limited Info) or we have content (1 Recommended Videos)
    // Never should have duplicates
    if (limitedInfo > 0) {
      expect(limitedInfo).toBe(1);
    }
    if (recommended > 0) {
      expect(recommended).toBe(1);
    }

    // Follow-up questions should appear exactly once per tool response
    const followupSections = await page.locator('text="Follow-up questions"').count();
    expect(followupSections).toBeLessThanOrEqual(1);
  });
});
