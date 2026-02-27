import { Page, TestInfo, expect } from "@playwright/test";

/**
 * Shared E2E test helpers for CopilotKit interaction.
 *
 * CopilotKit has an initial agent/connect handshake on page load. If a message
 * is submitted before this handshake completes, the message is silently
 * discarded. These helpers ensure the handshake is complete before interacting.
 *
 * The library page polls for video processing status in the background, so
 * `page.waitForLoadState("networkidle")` hangs indefinitely. We use a
 * verification-based approach instead: after pressing Enter we confirm the
 * user message appeared in the chat UI. If it didn't, we retry.
 */

/** Default placeholder text for the CopilotKit chat input. */
const CHAT_INPUT_PLACEHOLDER = "Ask about your videos...";

/** Maximum number of times to retry submitting a query if it gets silently discarded. */
const MAX_SUBMIT_RETRIES = 3;

/** Time to wait between submission retries (ms). */
const RETRY_DELAY_MS = 3000;

/**
 * Wait for CopilotKit to be ready to accept user input.
 *
 * Instead of a fixed 8-second wait for the handshake, we intercept the actual
 * CopilotKit POST request to /api/copilotkit and wait for it to complete.
 * This is deterministic: the handshake is done when the response arrives.
 *
 * On the library page, `page.waitForLoadState("networkidle")` never resolves
 * because the page polls for video status. Request interception avoids this.
 */
export async function waitForCopilotReady(page: Page): Promise<void> {
  const input = page.getByPlaceholder(CHAT_INPUT_PLACEHOLDER);
  await expect(input).toBeVisible({ timeout: 30_000 });

  // Wait for CopilotKit's initial handshake request to complete.
  // CopilotKit sends a POST to /api/copilotkit with 0 messages on mount.
  // We wait for this round-trip to finish, proving the agent is connected.
  // Use a short timeout (10s) because the handshake fires within 1-3s of page
  // load. If we miss it (already completed), we fall back to 5s which is enough
  // since the input is already visible and the handshake is done.
  try {
    await page.waitForResponse(
      (resp) =>
        resp.url().includes("/api/copilotkit") && resp.status() === 200,
      { timeout: 10_000 },
    );
  } catch {
    // Handshake already completed before we started listening, or the endpoint
    // returned a non-200 status. Since the input is already visible (checked
    // above), CopilotKit is likely ready. A short wait covers edge cases.
  }

  // IMPORTANT: Even after the handshake response arrives, CopilotKit needs
  // time to process it and fully initialize its internal state (thread setup,
  // tool registration, etc.). Without this buffer, messages sent immediately
  // after handshake may be silently discarded or processed incorrectly.
  // 5s is sufficient based on production observation (old fixed 8s wait minus
  // typical 1-3s handshake time).
  await page.waitForTimeout(5000);
}

/**
 * Submit a query to the CopilotKit chat and verify it was accepted.
 *
 * After pressing Enter, we verify that the user message text appears in the
 * chat UI. If CopilotKit silently discarded it (handshake not complete), we
 * retry up to MAX_SUBMIT_RETRIES times.
 */
export async function submitQuery(page: Page, query: string): Promise<void> {
  // Don't call waitForCopilotReady here — callers should ensure it's been
  // called once already (e.g., in beforeEach or via openChat). This avoids
  // paying the HANDSHAKE_WAIT_MS penalty on every follow-up query.

  for (let attempt = 1; attempt <= MAX_SUBMIT_RETRIES; attempt++) {
    const input = page.getByPlaceholder(CHAT_INPUT_PLACEHOLDER);
    await expect(input).toBeVisible({ timeout: 10_000 });
    await input.fill(query);
    await input.press("Enter");

    // Verify the user message appeared in the chat. Use a short prefix with
    // getByText (substring match) rather than exact CSS text= selector, because
    // CopilotKit may wrap the text in markdown or truncate it.
    const verifyText =
      query.length > 40 ? query.substring(0, 40) : query;
    try {
      await expect(
        page.getByText(verifyText, { exact: false }).first(),
      ).toBeVisible({ timeout: 10_000 });
      // Message was accepted — return
      return;
    } catch {
      if (attempt === MAX_SUBMIT_RETRIES) {
        throw new Error(
          `submitQuery: message "${verifyText}..." was not rendered in chat ` +
            `after ${MAX_SUBMIT_RETRIES} attempts. CopilotKit may not be ready.`,
        );
      }
      // Wait before retrying
      await page.waitForTimeout(RETRY_DELAY_MS);
    }
  }
}

/**
 * Wait for the copilot to finish responding to a query.
 *
 * Derives timeout from the current test's actual timeout (respects test.slow()),
 * leaving 30s headroom for subsequent assertions.
 *
 * Two-phase approach:
 * 1. Wait for the tool loading indicator ("Searching your video library...")
 *    to appear and then disappear — this confirms the backend is processing.
 * 2. Wait for actual response content (video cards, headings, or uncertainty
 *    indicators) to become visible, OR detect that the agent has finished
 *    responding (input re-enabled) even if the response is plain text.
 *
 * IMPORTANT: The loading indicator must NOT be in the final response locator
 * because it appears transiently during tool execution. Including it causes
 * premature resolution before the real response renders.
 */
export async function waitForResponse(
  page: Page,
  testInfo: TestInfo,
): Promise<void> {
  const timeout = Math.max(testInfo.timeout - 30_000, 60_000);

  // Phase 1: Wait for the tool loading indicator to appear (confirms backend
  // received and is processing the query). We use a short timeout since it may
  // have already appeared and disappeared by the time we check.
  const loadingText = page.getByText("Searching your video library...");
  try {
    await expect(loadingText).toBeVisible({ timeout: 30_000 });
  } catch {
    // Loading indicator may have already appeared and disappeared, or the
    // response may have rendered so quickly that the loading state was never
    // visible. Either way, proceed to phase 2.
  }

  // Phase 1b: Wait for loading indicator to disappear (tool execution complete).
  // Skip if it's already gone.
  try {
    await expect(loadingText).not.toBeVisible({ timeout: Math.min(timeout, 120_000) });
  } catch {
    // If loading text is still visible after 120s, proceed anyway and let
    // phase 2 handle the timeout.
  }

  // Phase 2: Wait for actual response content. These are the FINAL rendered
  // elements, not transient loading states. We race two strategies:
  //
  // Strategy A: Detect specific tool-rendered content (video cards, headings,
  //   uncertainty indicators). This is the preferred path when the agent uses tools.
  //
  // Strategy B: Detect that the agent finished responding by waiting for the chat
  //   input to be re-enabled AND a new assistant message to appear. This handles
  //   plain-text responses where the agent doesn't invoke tools (CopilotKit hides
  //   non-greeting markdown, but the response lifecycle still completes).
  const responseIndicator = page
    .getByText("Recommended Videos")
    .or(page.getByText("Sources"))
    .or(page.locator('a[href*="/videos/"]'))
    .or(page.getByText("Limited Information"))
    .or(page.getByText("No relevant content"));

  // Strategy A: wait for tool-rendered content
  const strategyA = expect(responseIndicator.first()).toBeVisible({ timeout })
    .then(() => 'tool-rendered');

  // Strategy B: wait for response lifecycle to complete (input re-enabled after
  // being disabled during agent processing, plus at least one assistant message
  // exists beyond the initial greeting)
  const strategyB = (async () => {
    const chatInput = page.getByPlaceholder("Ask about your videos...");
    // Wait for the input to become disabled (agent is processing)
    try {
      await expect(chatInput).toBeDisabled({ timeout: 30_000 });
    } catch {
      // Input may never have been disabled if response was instant
    }
    // Wait for the input to be re-enabled (agent finished)
    await expect(chatInput).toBeEnabled({ timeout });
    // Give a brief moment for any remaining renders to complete
    await page.waitForTimeout(2_000);
    // Verify at least 2 assistant message divs exist (greeting + response)
    const assistantMessages = page.locator('.copilotKitAssistantMessage');
    const count = await assistantMessages.count();
    if (count < 2) {
      throw new Error(`Expected at least 2 assistant messages, found ${count}`);
    }
    return 'lifecycle-complete';
  })();

  await Promise.race([strategyA, strategyB]);
}

/**
 * Open the CopilotKit chat sidebar.
 *
 * Navigates to the given path with `?chat=open` if not already on it.
 * Waits for the chat input to become visible and CopilotKit to be ready.
 */
export async function openChat(
  page: Page,
  path: string = "/library",
): Promise<void> {
  const separator = path.includes("?") ? "&" : "?";
  await page.goto(`${path}${separator}chat=open`);
  await waitForCopilotReady(page);
}

/**
 * Open the CopilotKit chat sidebar by clicking the "Open AI Assistant" button.
 *
 * Useful when the page is already loaded and we need to toggle the sidebar.
 */
export async function openChatViaButton(page: Page): Promise<void> {
  const button = page.getByRole("button", { name: /open ai assistant/i });
  await expect(button).toBeVisible({ timeout: 15_000 });
  await button.click();
  await waitForCopilotReady(page);
}

/**
 * Wait for the copilot assistant response to appear (non-tool-specific).
 *
 * This waits for the tool loading lifecycle to complete and for a response
 * message to be rendered in the chat area. Useful for tests that check message
 * count or generic response behavior rather than specific tool output.
 */
export async function waitForAssistantResponse(
  page: Page,
  options: { timeout?: number } = {},
): Promise<void> {
  const timeout = options.timeout ?? 120_000;

  // Wait for "Searching your video library..." loading indicator to appear
  // and then disappear (tool call lifecycle)
  const loadingText = page.getByText("Searching your video library...");
  try {
    await expect(loadingText).toBeVisible({ timeout: 30_000 });
  } catch {
    // Loading indicator may have already appeared and disappeared
  }

  // Wait for loading indicator to disappear
  await expect(loadingText).not.toBeVisible({ timeout });

  // Also wait for any spinner/loading animations to settle
  const spinners = page.locator(
    '[class*="animate-spin"], [class*="loading"], [role="progressbar"]',
  );
  if ((await spinners.count()) > 0) {
    await expect(spinners.first()).not.toBeVisible({ timeout: 30_000 });
  }
}

/**
 * Get the API base URL from environment or default to localhost.
 */
export function getApiUrl(): string {
  return process.env.API_URL || "http://localhost:8000";
}

/**
 * Fetch a completed, seeded video ID from the API.
 *
 * Global-setup seeds 15+ videos and waits for processing to complete. This
 * helper queries the library API to find one that's ready, eliminating the
 * need to re-ingest and wait for processing in individual tests.
 *
 * Returns the video ID string, or null if no videos are available.
 */
export async function getSeededVideoId(): Promise<string | null> {
  const API_URL = getApiUrl();
  try {
    const response = await fetch(
      `${API_URL}/api/v1/library/videos?page_size=1`,
    );
    if (!response.ok) return null;
    const data = await response.json();
    const videos = data.videos || data.items || [];
    if (videos.length === 0) return null;
    return videos[0].id || videos[0].video_id || null;
  } catch {
    return null;
  }
}

/**
 * Wait for a video to finish processing by polling the API directly.
 *
 * Unlike the old page-reload approach, this polls the backend API endpoint
 * (`GET /api/v1/jobs/video/{id}/progress`) without touching the browser.
 * This eliminates CopilotKit URL oscillation interference, ERR_ABORTED
 * errors from page.reload(), and DOM-based detection fragility.
 *
 * OPTIMIZATION: First checks if the video already has segments (meaning it
 * was processed in a previous run). This avoids polling the job endpoint
 * for 3 minutes when the video is already done.
 *
 * @returns true if processing completed, false if timed out or failed.
 */
export async function waitForVideoProcessingViaApi(
  videoId: string,
  timeout: number = 180_000,
): Promise<boolean> {
  const API_URL = getApiUrl();
  const startTime = Date.now();
  const pollInterval = 3000;

  console.log(
    `[waitForVideoProcessingViaApi] Polling for video ${videoId} (timeout: ${timeout / 1000}s)`,
  );

  // Quick check: see if the video already has segments (already processed).
  // This covers the common case where the video was ingested in a prior run.
  try {
    const libraryResp = await fetch(
      `${API_URL}/api/v1/library/videos/${videoId}`,
    );
    if (libraryResp.ok) {
      const videoData = await libraryResp.json();
      const segmentCount =
        videoData.segment_count ??
        videoData.segments?.length ??
        videoData.total_segments ??
        0;
      if (segmentCount > 0) {
        console.log(
          `[waitForVideoProcessingViaApi] Video ${videoId} already has ${segmentCount} segments — skipping poll`,
        );
        return true;
      }
    }
  } catch {
    // Library endpoint unavailable — fall through to job polling
  }

  while (Date.now() - startTime < timeout) {
    try {
      const response = await fetch(
        `${API_URL}/api/v1/jobs/video/${videoId}/progress`,
      );
      if (response.ok) {
        const data = await response.json();
        const status = data.status || data.state;
        if (status === "completed" || status === "complete") {
          const elapsed = Math.round((Date.now() - startTime) / 1000);
          console.log(
            `[waitForVideoProcessingViaApi] Video ${videoId} completed in ${elapsed}s`,
          );
          return true;
        }
        if (status === "failed" || status === "error") {
          console.error(
            `[waitForVideoProcessingViaApi] Video ${videoId} failed: ${JSON.stringify(data)}`,
          );
          return false;
        }
      } else if (response.status === 404) {
        // No active job found. The video may have already been processed
        // (job record expired/cleaned up). Check library again.
        try {
          const checkResp = await fetch(
            `${API_URL}/api/v1/library/videos/${videoId}`,
          );
          if (checkResp.ok) {
            const checkData = await checkResp.json();
            const count =
              checkData.segment_count ??
              checkData.segments?.length ??
              checkData.total_segments ??
              0;
            if (count > 0) {
              console.log(
                `[waitForVideoProcessingViaApi] Job 404 but video has ${count} segments — treating as done`,
              );
              return true;
            }
          }
        } catch {
          // Ignore — will retry on next poll
        }
      }
    } catch {
      // Network error — retry
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  console.error(
    `[waitForVideoProcessingViaApi] Video ${videoId} timed out after ${timeout / 1000}s`,
  );
  return false;
}
