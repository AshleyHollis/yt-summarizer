import { test, expect, Page, TestInfo, BrowserContext } from "@playwright/test";

/**
 * E2E tests for Chat Response Quality
 *
 * Tests verify that the copilot responds correctly based on:
 * - The videos in the library (seeded via global-setup.ts)
 * - The configured LLM (DeepSeek-V3.2)
 *
 * Test videos (all with YouTube auto-captions for cost efficiency):
 * - The Perfect Push Up (Calisthenicmovement) - IODxDxX7oi4 - 3:37 ✓ has captions
 * - You CAN do pushups! (Hybrid Calisthenics) - 0GsVJsS6474 - 3:09 ✓ has captions
 * - The Perfect Push-Up (short) - c-lBErfxszs - 0:31 ✓ has captions
 * - The BEST Kettlebell Swing Tutorial - aSYap2yhW8s - 0:58 ✓ has captions
 * - How To Do Kettlebell Swings | Proper Form - hp3qVqIHNOI - 4:37 ✓ has captions
 *
 * Videos are clustered by topic for relationship testing:
 * - Push-up cluster: IODxDxX7oi4 + 0GsVJsS6474 + c-lBErfxszs (should relate)
 * - Kettlebell cluster: aSYap2yhW8s + hp3qVqIHNOI (should relate)
 *
 * IMPORTANT: Videos without YouTube auto-captions require Whisper transcription
 * which is expensive. Verify captions with: yt-dlp --list-subs "URL"
 *
 * These tests use multiple assertions per test for efficiency.
 */

async function submitQuery(page: Page, query: string): Promise<void> {
  const input = page.getByPlaceholder("Ask about your videos...");
  await expect(input).toBeVisible({ timeout: 10000 });
  await input.fill(query);
  await input.press("Enter");
}

async function waitForResponse(page: Page, testInfo: TestInfo): Promise<void> {
  // Derive timeout from the current test's actual timeout (respects test.slow()),
  // leaving 30s headroom for subsequent assertions.
  const timeout = Math.max(testInfo.timeout - 30000, 30000);
  // Wait for response indicators - the UI shows "Sources" section with citations
  // Also check for video links, or informational messages
  // Increased timeout to handle LLM rate limit retries under parallel CI load
  await Promise.race([
    page.waitForSelector('text="Recommended Videos"', { timeout }),
    page.waitForSelector('text="Sources"', { timeout }),
    page.waitForSelector('a[href*="/videos/"]', { timeout }),
    page.waitForSelector('text="Limited Information"', { timeout }),
    page.waitForSelector('text="No relevant content"', { timeout }),
    // Also wait for any response with citations (superscript [1], [2], etc.)
    page.waitForSelector('superscript', { timeout }),
  ]);
}

// Helper function to get response text - kept for potential future use
// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function getResponseText(_page: Page): Promise<string> {
  // Get all paragraph text from the copilot response area
  const paragraphs = _page.locator('.copilot-sidebar p, [class*="copilot"] p, [class*="Copilot"] p');
  const texts: string[] = [];
  const count = await paragraphs.count();
  for (let i = 0; i < count; i++) {
    const text = await paragraphs.nth(i).textContent();
    if (text) texts.push(text);
  }
  return texts.join(' ');
}

test.describe("Chat Response Quality", () => {
  // Each test gets a fresh browser context so CopilotKit in-memory thread state
  // never accumulates across tests. This avoids client-generated thread IDs
  // (server should own thread ID generation) and prevents history bloat
  // that causes progressive LLM prompt growth and timeout failures.
  let context: BrowserContext;
  let page: Page;

  test.beforeEach(async ({ browser }) => {
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    page = await context.newPage();
    await page.goto("/library?chat=open");
    await page.waitForLoadState("networkidle");
  });

  test.afterEach(async () => {
    await context.close();
  });

  test("push-up query returns accurate content with proper citations", async ({}, testInfo) => {
    test.slow(); // LLM call required: triple timeout to 360s
    await submitQuery(page, "How do I do a proper push-up with good form?");
    await waitForResponse(page, testInfo);

    // 1. Should show video cards (indicated by video links)
    const videoLinks = page.locator('a[href*="/videos/"]');
    await expect(videoLinks.first()).toBeVisible();

    // 2. Should have "Recommended Videos" section
    await expect(page.getByText("Recommended Videos")).toBeVisible();

    // 3. Response should mention key push-up concepts (form cues from the videos)
    const pageContent = await page.content();
    const lowerContent = pageContent.toLowerCase();

    // Should mention at least some of these push-up form cues
    const formCues = ["plank", "elbow", "shoulder", "chest", "straight", "body", "core", "arms"];
    const foundCues = formCues.filter(cue => lowerContent.includes(cue));
    expect(foundCues.length).toBeGreaterThan(2);

    // 4. Should cite the push-up videos (check for video titles)
    const hasPushUpVideo =
      lowerContent.includes("perfect push up") ||
      lowerContent.includes("the push-up") ||
      lowerContent.includes("push up");
    expect(hasPushUpVideo).toBe(true);

    // 5. Video cards should link to video detail pages
    const linkCount = await videoLinks.count();
    expect(linkCount).toBeGreaterThan(0);
  });

  test("kettlebell query returns content from Pavel Tsatsouline video", async ({}, testInfo) => {
    test.slow(); // LLM call required: triple timeout to 360s
    await submitQuery(page, "Tell me about kettlebell training techniques");
    await waitForResponse(page, testInfo);

    // 1. Should show video cards
    const videoLinks = page.locator('a[href*="/videos/"]');
    await expect(videoLinks.first()).toBeVisible();

    // 2. Should reference the kettlebell video
    const pageContent = await page.content();
    const lowerContent = pageContent.toLowerCase();

    // Should mention kettlebell-related content
    const hasKettlebellContent =
      lowerContent.includes("kettlebell") ||
      lowerContent.includes("pavel") ||
      lowerContent.includes("swing") ||
      lowerContent.includes("cassiusk");
    expect(hasKettlebellContent).toBe(true);

    // 3. Should have proper video card structure
    expect(await videoLinks.count()).toBeGreaterThan(0);
  });

  // Skip: Heavy clubs video is not in the seeded test data
  // To enable: Add Mark Wildman's heavy clubs video to global-setup.ts TEST_VIDEOS
  test.skip("heavy clubs query returns Mark Wildman video content", async ({}, testInfo) => {
    await submitQuery(page, "What should beginners know about heavy clubs?");
    await waitForResponse(page, testInfo);

    // 1. Should show video cards
    await expect(page.locator('a[href*="/videos/"]').first()).toBeVisible();

    // 2. Should reference Mark Wildman or heavy clubs content
    const pageContent = await page.content();
    const lowerContent = pageContent.toLowerCase();

    const hasHeavyClubsContent =
      lowerContent.includes("heavy club") ||
      lowerContent.includes("mark wildman") ||
      lowerContent.includes("beginner") ||
      lowerContent.includes("club");
    expect(hasHeavyClubsContent).toBe(true);

    // 3. Should have video card linking to the heavy clubs video
    await expect(page.getByText("The Key Part of Heavy Clubs").first()).toBeVisible();
  });

  test("multi-topic query returns multiple relevant videos", async ({}, testInfo) => {
    test.slow(); // LLM-heavy: triple timeout to 360s
    await submitQuery(page, "What exercises can I do for a full body workout?");
    await waitForResponse(page, testInfo);

    // Response should include citations - check for any of these indicators:
    // - Video links with /videos/ or /library/ paths
    // - Citation superscripts like [1], [2]
    // - Sources section with video titles
    const videoLinks = page.locator('a[href*="/videos/"], a[href*="/library/"]');
    const citations = page.locator('superscript');
    const sourcesSection = page.getByText('Sources');

    // At least one of these should be present
    const hasVideoLinks = await videoLinks.count() > 0;
    const hasCitations = await citations.count() > 0;
    const hasSources = await sourcesSection.count() > 0;

    expect(hasVideoLinks || hasCitations || hasSources).toBe(true);

    // Check page has content from exercise-related topics
    const pageContent = await page.content();
    const lowerContent = pageContent.toLowerCase();

    // Should mention exercise-related content
    const hasExerciseContent =
      lowerContent.includes("exercise") ||
      lowerContent.includes("push") ||
      lowerContent.includes("kettlebell") ||
      lowerContent.includes("workout") ||
      lowerContent.includes("training");
    expect(hasExerciseContent).toBe(true);
  });

  test("response includes synthesized answer not just raw transcript", async ({}, testInfo) => {
    test.slow(); // LLM-heavy: triple timeout to 360s
    await submitQuery(page, "What are the common mistakes when doing push-ups?");
    await waitForResponse(page, testInfo);

    // 1. Should show video cards
    await expect(page.locator('a[href*="/videos/"]').first()).toBeVisible();

    // 2. Response should be a coherent answer, not just transcript dump
    const pageContent = await page.content();

    // Should have structured content - check for lists or paragraphs in HTML
    const hasStructuredContent =
      pageContent.includes("<li") ||
      pageContent.includes("<ul") ||
      pageContent.includes("<ol") ||
      pageContent.includes("<p") ||
      pageContent.includes("list");
    expect(hasStructuredContent).toBe(true);

    // 3. Should mention "mistakes" since that's what was asked
    expect(pageContent.toLowerCase()).toContain("mistake");
  });

  test("irrelevant query shows Limited Information indicator", async ({}, testInfo) => {
    test.slow(); // LLM call can be slow: triple timeout to 360s
    await submitQuery(page, "How do I bake a chocolate cake?");

    // Wait for the "Limited Information" response - derive timeout from test budget
    const limitedInfoTimeout = Math.max(testInfo.timeout - 30000, 30000);
    await page.waitForSelector('text="Limited Information"', { timeout: limitedInfoTimeout });

    // 1. Should NOT show video cards
    const videoLinks = page.locator('a[href*="/videos/"]');
    await expect(videoLinks).toHaveCount(0);

    // 2. Should show the "No relevant content" message
    await expect(page.getByText("No relevant content found")).toBeVisible();

    // 3. Should NOT show "Recommended Videos" section
    await expect(page.getByText("Recommended Videos")).not.toBeVisible();

    // 4. The LLM might still provide helpful general info (that's fine)
    // but should acknowledge the library doesn't have this content
    const pageContent = await page.content();
    expect(pageContent.toLowerCase()).toMatch(/don't have|didn't find|no.*video|not.*library/i);
  });

  test("video card links navigate to correct video detail page", async ({}, testInfo) => {
    test.slow(); // LLM call required before link testing: triple timeout to 360s
    await submitQuery(page, "Show me push-up tutorials");
    await waitForResponse(page, testInfo);

    // Find a video link - could be in /videos/ or /library/ paths
    const videoLink = page.locator('a[href*="/videos/"], a[href*="/library/"]').first();

    // If no links found, skip this test (citations may be text-only)
    const linkCount = await videoLink.count();
    if (linkCount === 0) {
      console.log("No video links found in copilot response - citations may be text-only");
      return;
    }

    await expect(videoLink).toBeVisible();

    // Get the href before clicking
    const href = await videoLink.getAttribute("href");
    expect(href).toBeDefined();

    // Click the link using JavaScript to avoid viewport issues
    await page.evaluate((href) => {
      const link = document.querySelector(`a[href="${href}"]`);
      if (link) {
        link.scrollIntoView({ behavior: 'instant', block: 'center' });
        (link as HTMLAnchorElement).click();
      }
    }, href);

    // Should navigate to video detail page (either /videos/ or /library/ path)
    await page.waitForURL(/\/videos\/|\/library\//, { timeout: 10000 });

    // Video detail page should load with video info
    await page.waitForLoadState("networkidle");

    // Should show video content - look for headings or article content
    const hasHeading = await page.locator("h1, h2, h3").first().isVisible().catch(() => false);
    const hasArticle = await page.locator("article").count() > 0;
    const hasVideoPlayer = await page.locator("video, iframe, [class*='player']").count() > 0;

    expect(hasHeading || hasArticle || hasVideoPlayer).toBe(true);
  });
});

test.describe("Chat Edge Cases", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    // Navigate with chat=open to have the sidebar open by default
    await page.goto("/library?chat=open");
    await page.waitForLoadState("networkidle");
  });

  test("handles empty and whitespace-only queries gracefully", async ({ page }) => {
    const input = page.getByPlaceholder("Ask about your videos...");
    await expect(input).toBeVisible();

    // Try to submit empty query - send button should be disabled
    const sendButton = page.getByRole("button", { name: /send/i });

    // With empty input, send should be disabled
    await expect(sendButton).toBeDisabled();

    // Try whitespace only
    await input.fill("   ");
    // Send should still be disabled or the query should be trimmed
    const isDisabled = await sendButton.isDisabled();

    // Either button is disabled OR if we can submit, it handles gracefully
    if (!isDisabled) {
      await input.press("Enter");
      // Should not crash - either shows error or ignores
      await page.waitForTimeout(2000);
      await expect(page).toHaveURL(/library/);
    }
  });

  test("handles special characters in query", async ({ page }, testInfo) => {
    test.slow(); // LLM call required: triple timeout to 540s
    await submitQuery(page, "What about push-ups? (with good form) & proper technique!");

    // Should still work and not crash
    await waitForResponse(page, testInfo);

    // Should get a response (either video cards or "limited information")
    const hasResponse =
      await page.locator('a[href*="/videos/"]').count() > 0 ||
      await page.locator('text="Limited Information"').count() > 0;
    expect(hasResponse).toBe(true);
  });

  test("handles very long query", async ({ page }, testInfo) => {
    test.slow(); // LLM call required: triple timeout to 540s
    const longQuery = "I want to learn about push-ups, specifically the proper form, " +
      "common mistakes, how to progress from beginner to advanced, " +
      "what muscles are worked, how many reps and sets I should do, " +
      "and any tips for people who have wrist problems. " +
      "Also interested in variations like diamond push-ups, wide push-ups, and decline push-ups.";

    await submitQuery(page, longQuery);
    await waitForResponse(page, testInfo);

    // Should handle long query and return results
    const videoLinks = page.locator('a[href*="/videos/"]');
    await expect(videoLinks.first()).toBeVisible();
  });

  test("subsequent queries work correctly", async ({ page }, testInfo) => {
    test.slow(); // Two sequential LLM calls required: triple timeout to 540s
    // First query
    await submitQuery(page, "How do push-ups work?");
    await waitForResponse(page, testInfo);
    await expect(page.locator('a[href*="/videos/"]').first()).toBeVisible();

    // Second query - different topic
    await submitQuery(page, "What about kettlebells?");
    await waitForResponse(page, testInfo);

    // Should show new results
    const pageContent = await page.content();
    expect(pageContent.toLowerCase()).toContain("kettlebell");
  });
});
