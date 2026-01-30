import { test, expect, Page } from "@playwright/test";

/**
 * E2E tests for Single Response Verification
 *
 * Tests verify that each user message produces exactly ONE assistant response.
 * This catches regressions where duplicate messages appear in the chat.
 *
 * Bug context: Issue where tool results (e.g., queryLibrary) were being
 * rendered multiple times, causing duplicate "Limited Information" cards.
 */

async function openChat(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/library");
  await page.waitForLoadState("networkidle");

  // Open the AI assistant sidebar
  const openButton = page.getByRole("button", { name: "Open AI Assistant" });
  await expect(openButton).toBeVisible({ timeout: 10000 });
  await openButton.click();

  // Wait for chat to be ready
  await expect(page.getByRole("textbox", { name: "Ask about your videos..." })).toBeVisible();
}

async function sendMessage(page: Page, message: string): Promise<void> {
  const input = page.getByRole("textbox", { name: "Ask about your videos..." });
  await input.fill(message);
  await input.press("Enter");
}

async function waitForAssistantResponse(page: Page, timeout = 60000): Promise<void> {
  // Wait for any response to complete (not in progress state)
  await page.waitForFunction(
    () => {
      // Look for spinner/loading indicators to disappear
      const spinners = document.querySelectorAll('[class*="animate-spin"]');
      const loadingText = document.body.textContent?.includes("Searching your video library...");
      return spinners.length === 0 && !loadingText;
    },
    { timeout }
  );

  // Additional wait for any tool results to finish rendering
  await page.waitForTimeout(1000);
}

function countAssistantMessageBlocks(page: Page) {
  // Count the number of "Limited Information" cards (indicator of queryLibrary tool response)
  return page.locator('text="Limited Information"').count();
}

// Helper function for counting tool progress indicators - reserved for future use
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _countToolInProgressIndicators(_page: Page) {
  return _page.locator('text="Searching your video library..."').count();
}

test.describe("Single Response Per Message", () => {
  test("simple greeting produces exactly one response", async ({ page }) => {
    await openChat(page);

    // Send a simple greeting that doesn't trigger tools
    await sendMessage(page, "Hello, how are you?");

    // Wait for response
    await page.waitForTimeout(3000);

    // Count user messages (should be 1)
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _userMessages = page.locator('[class*="UserMessage"], [class*="userMessage"]');
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
    await openChat(page);

    // Send a query that triggers the queryLibrary tool
    await sendMessage(page, "What videos do I have about exercise?");

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
    await openChat(page);

    // First message
    await sendMessage(page, "Hello!");
    await page.waitForTimeout(2000);

    // Second message - triggers tool
    await sendMessage(page, "What videos do I have?");
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
    await openChat(page);

    // Send query
    await sendMessage(page, "Tell me about the videos in my library");
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
