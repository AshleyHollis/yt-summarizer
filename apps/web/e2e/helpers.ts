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
 * Time to wait for CopilotKit's initial agent/connect handshake (ms).
 *
 * On the library page, `page.waitForLoadState("networkidle")` never resolves
 * because the page polls for video status. So we simply wait a fixed period
 * that is long enough for the handshake to complete in CI.
 */
const HANDSHAKE_WAIT_MS = 8000;

/**
 * Wait for CopilotKit to be ready to accept user input.
 *
 * This waits for the chat input to be visible and then waits a fixed period
 * for the initial agent/connect handshake to complete. We use a fixed wait
 * rather than networkidle because the library page polls continuously and
 * networkidle never resolves (causing test timeout errors that bypass
 * Promise.race catch handlers).
 */
export async function waitForCopilotReady(page: Page): Promise<void> {
  const input = page.getByPlaceholder(CHAT_INPUT_PLACEHOLDER);
  await expect(input).toBeVisible({ timeout: 30_000 });

  // Fixed wait for CopilotKit handshake. We intentionally do NOT use
  // page.waitForLoadState("networkidle") because on the library page it never
  // resolves (the page polls continuously) and when a Playwright test timeout
  // fires, the error bypasses Promise.race catch handlers, consuming the
  // entire test timeout budget.
  await page.waitForTimeout(HANDSHAKE_WAIT_MS);
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
 * Uses Playwright's `locator.or()` to wait for any response indicator rather
 * than racing multiple waitForSelector calls (which can cause unhandled
 * rejections when they all fail).
 */
export async function waitForResponse(
  page: Page,
  testInfo: TestInfo,
): Promise<void> {
  const timeout = Math.max(testInfo.timeout - 30_000, 60_000);

  // Build a composite locator that matches ANY response indicator.
  // This avoids the race condition of multiple waitForSelector calls where
  // losing selectors throw unhandled errors.
  const responseIndicator = page
    .getByText("Recommended Videos")
    .or(page.getByText("Sources"))
    .or(page.locator('a[href*="/videos/"]'))
    .or(page.getByText("Limited Information"))
    .or(page.getByText("No relevant content"))
    .or(page.getByText("Searching your video library..."));

  await expect(responseIndicator.first()).toBeVisible({ timeout });
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
 * This waits for loading spinners/indicators to disappear and for a response
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
  try {
    await page.waitForSelector('text="Searching your video library..."', {
      timeout: 30_000,
    });
  } catch {
    // Loading indicator may have already appeared and disappeared
  }

  // Wait for loading indicator to disappear
  await expect(
    page.getByText("Searching your video library..."),
  ).not.toBeVisible({ timeout });

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
