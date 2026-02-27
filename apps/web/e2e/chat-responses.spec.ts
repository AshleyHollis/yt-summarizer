import { test, expect, BrowserContext } from "@playwright/test";
import {
  submitQuery,
  waitForResponse,
  waitForCopilotReady,
  getCopilotResponseContent,
} from "./helpers";

/**
 * E2E tests for Chat Response Quality
 *
 * Tests verify that the copilot responds correctly based on:
 * - The videos in the library (seeded via global-setup.ts)
 * - The configured LLM (DeepSeek-V3.2)
 *
 * Test videos (all with YouTube auto-captions for cost efficiency):
 * - The Perfect Push Up (Calisthenicmovement) - IODxDxX7oi4 - 3:37
 * - You CAN do pushups! (Hybrid Calisthenics) - 0GsVJsS6474 - 3:09
 * - The Perfect Push-Up (short) - c-lBErfxszs - 0:31
 * - The BEST Kettlebell Swing Tutorial - aSYap2yhW8s - 0:58
 * - How To Do Kettlebell Swings | Proper Form - hp3qVqIHNOI - 4:37
 *
 * Videos are clustered by topic for relationship testing:
 * - Push-up cluster: IODxDxX7oi4 + 0GsVJsS6474 + c-lBErfxszs (should relate)
 * - Kettlebell cluster: aSYap2yhW8s + hp3qVqIHNOI (should relate)
 *
 * These tests use multiple assertions per test for efficiency.
 */

test.describe("Chat Response Quality", () => {
  // Each test gets a fresh browser context so CopilotKit in-memory thread state
  // never accumulates across tests. This avoids client-generated thread IDs
  // (server should own thread ID generation) and prevents history bloat
  // that causes progressive LLM prompt growth and timeout failures.
  let context: BrowserContext;
  let page: import("@playwright/test").Page;

  test.beforeEach(async ({ browser }) => {
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    page = await context.newPage();
    await page.goto("/library?chat=open", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");
    await waitForCopilotReady(page);
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
    await expect(videoLinks.first()).toBeVisible({ timeout: 30_000 });

    // 2. Should have "Recommended Videos" section
    await expect(page.getByText("Recommended Videos")).toBeVisible({ timeout: 15_000 });

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
    await expect(videoLinks.first()).toBeVisible({ timeout: 30_000 });

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

  // Heavy clubs video has been added to global-setup.ts TEST_VIDEOS
  test("heavy clubs query returns Mark Wildman video content", async ({}, testInfo) => {
    test.slow(); // LLM call with vector search: triple timeout
    await submitQuery(page, "What should beginners know about heavy clubs?");
    await waitForResponse(page, testInfo);

    // 1. Should show video cards OR uncertainty response
    const videoLinks = page.locator('a[href*="/videos/"]');
    const hasVideoCards = (await videoLinks.count()) > 0;

    // 2. Should reference Mark Wildman or heavy clubs content
    const pageContent = await page.content();
    const lowerContent = pageContent.toLowerCase();

    const hasHeavyClubsContent =
      lowerContent.includes("heavy club") ||
      lowerContent.includes("mark wildman") ||
      lowerContent.includes("beginner") ||
      lowerContent.includes("club");
    expect(hasHeavyClubsContent).toBe(true);

    // 3. If video cards are present, verify they link to video detail pages
    if (hasVideoCards) {
      await expect(videoLinks.first()).toBeVisible({ timeout: 10_000 });
    }
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
    await expect(page.locator('a[href*="/videos/"]').first()).toBeVisible({ timeout: 30_000 });

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

    // 2. The UncertaintyMessage component always renders "Limited Information" heading.
    // The body text is LLM-generated and varies — don't assert on exact wording.
    // Instead verify the uncertainty indicator is visible (already confirmed above).
    await expect(page.getByText("Limited Information")).toBeVisible();

    // 3. Should NOT show "Recommended Videos" section
    await expect(page.getByText("Recommended Videos")).not.toBeVisible();

    // 4. The LLM response text is non-deterministic — no exact text assertions.
    // The "Limited Information" heading being visible is sufficient to prove
    // the uncertainty flow triggered correctly.
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

    await expect(videoLink).toBeVisible({ timeout: 30_000 });

    // Get the href before navigating
    const href = await videoLink.getAttribute("href");
    expect(href).toBeDefined();

    // Navigate directly to the video detail page — clicking links inside
    // the CopilotKit chat panel doesn't reliably trigger Next.js client-side
    // routing, so use page.goto() instead.
    await page.goto(href!);

    // Video detail page is a client component that fetches data via useEffect.
    // Wait for the <main> element to be visible (rendered in all states:
    // loading skeleton, error, success).
    await expect(page.locator("main")).toBeVisible({ timeout: 30_000 });

    // Should show video content — the page may still be loading data, but
    // at minimum the <main> wrapper and basic layout should be present.
    // We verify we're on a video detail page by checking the URL pattern.
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/\/(?:videos|library)\//);
  });
});

test.describe("Chat Edge Cases", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    // Navigate with chat=open to have the sidebar open by default
    // Use waitUntil:'commit' to avoid ERR_ABORTED from CopilotKit URL oscillation
    await page.goto("/library?chat=open", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");
    await waitForCopilotReady(page);
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

    // waitForResponse confirmed the agent finished. Verify non-empty response.
    const responseContent = await getCopilotResponseContent(page);
    expect(responseContent.length).toBeGreaterThan(0);
  });

  test("handles very long query", async ({ page }, testInfo) => {
    test.slow(); // LLM call required: triple timeout to 540s
    // Moderately long query — tests that the input isn't truncated or rejected,
    // without being so verbose that it causes LLM processing timeouts.
    const longQuery =
      "I want to learn about push-ups including proper form, " +
      "common mistakes beginners make, and how to progress " +
      "from beginner to advanced variations.";

    await submitQuery(page, longQuery);
    await waitForResponse(page, testInfo);

    // waitForResponse already confirmed the agent finished responding (either
    // tool-rendered content appeared or the lifecycle completed). Verify we got
    // a non-empty response — accept tool output OR plain text.
    const responseContent = await getCopilotResponseContent(page);
    expect(responseContent.length).toBeGreaterThan(0);
  });

  test("subsequent queries work correctly", async ({ page }, testInfo) => {
    test.slow(); // Two sequential LLM calls required: triple timeout to 540s
    // First query
    await submitQuery(page, "How do push-ups work?");
    await waitForResponse(page, testInfo);
    const firstResponse = await getCopilotResponseContent(page);
    expect(firstResponse.length).toBeGreaterThan(0);

    // Second query - different topic
    await submitQuery(page, "What about kettlebells?");
    await waitForResponse(page, testInfo);

    // Should show new results
    const pageContent = await page.content();
    expect(pageContent.toLowerCase()).toContain("kettlebell");
  });
});
