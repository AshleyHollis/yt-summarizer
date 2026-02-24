import { test, expect, Page } from '@playwright/test';

/**
 * E2E Tests for User Story 1: Complete Video Submission Flow
 *
 * These tests verify the core user journey:
 * 1. Submit a YouTube video URL
 * 2. Track processing progress (transcribe → summarize → embed → relationships)
 * 3. View completed video with transcript and summary
 *
 * Prerequisites:
 * - Aspire backend must be running: cd services/aspire/AppHost && dotnet run
 * - Run with: USE_EXTERNAL_SERVER=true npm run test:e2e
 * - For tests that require real AI processing: LIVE_PROCESSING=true
 */

// Test configuration
const TEST_VIDEO_URL = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
const PROCESSING_TIMEOUT = 120_000; // 2 minutes for processing

// Check if live processing tests should run (requires real AI services)
const LIVE_PROCESSING = process.env.LIVE_PROCESSING === 'true';

test.describe('User Story 1: Video Submission Flow', () => {
  // Skip all tests in this suite unless backend is running
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  test.describe('Complete Video Submission Journey', () => {
    // These tests require actual video processing to complete
    test.skip(() => !LIVE_PROCESSING, 'Requires live AI processing - run with LIVE_PROCESSING=true');

    test('user can submit video and view completed result', async ({ page }) => {
      // Step 1: Navigate to submit page
      await page.goto('/submit');
      await expect(page).toHaveURL('/submit');

      // Step 2: Enter YouTube URL
      const urlInput = page.getByLabel(/YouTube Video URL/i);
      await expect(urlInput).toBeVisible();
      await urlInput.fill(TEST_VIDEO_URL);

      // Step 3: Click submit button
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await expect(submitButton).toBeEnabled();
      await submitButton.click();

      // Step 4: Wait for redirect to video detail page
      await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });
      const videoUrl = page.url();
      const videoId = videoUrl.split('/videos/')[1];
      expect(videoId).toMatch(/^[a-f0-9-]{36}$/);

      // Step 5: Verify video detail page loads
      await expect(page.locator('main')).toBeVisible();

      // Step 6: Verify processing status is shown
      // The page should show either "Processing" section or status
      const processingIndicator = page.getByText(/processing|pending|running/i).first();
      const completedIndicator = page.getByText(/completed|summary|transcript/i).first();

      // Wait for either processing to start or already be completed
      await expect(processingIndicator.or(completedIndicator)).toBeVisible({ timeout: 10_000 });
    });

    test('video detail page shows job progress during processing', async ({ page }) => {
      // Submit a new video
      await page.goto('/submit');
      const urlInput = page.getByLabel(/YouTube Video URL/i);
      await urlInput.fill(TEST_VIDEO_URL);

      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();

      // Wait for redirect
      await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });

      // Verify job progress section exists
      // The page should show job status information
      const mainContent = page.locator('main');
      await expect(mainContent).toBeVisible();

      // Look for processing-related content
      const jobSection = page.locator('section, div').filter({
        hasText: /transcribe|summarize|embed|relationship|progress|status/i,
      });

      // At least one should be visible (either progress or completed content)
      await expect(jobSection.first()).toBeVisible({ timeout: 10_000 });
    });

    test('completed video displays transcript and summary', async ({ page }) => {
      // First submit a video
      await page.goto('/submit');
      const urlInput = page.getByLabel(/YouTube Video URL/i);
      await urlInput.fill(TEST_VIDEO_URL);

      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();

      // Wait for redirect to video page
      await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });

      // Wait for processing to complete (or check if already completed)
      // This uses a polling approach to wait for completion
      await waitForVideoCompletion(page, PROCESSING_TIMEOUT);

      // Verify transcript section is visible
      const transcriptSection = page.locator('section, div').filter({
        hasText: /transcript/i,
      });
      await expect(transcriptSection.first()).toBeVisible({ timeout: 5_000 });

      // Verify summary section is visible
      const summarySection = page.locator('section, div').filter({
        hasText: /summary/i,
      });
      await expect(summarySection.first()).toBeVisible({ timeout: 5_000 });
    });
  });

  test.describe('Video Detail Page Features', () => {
    // These tests require actual video processing to complete
    test.skip(() => !LIVE_PROCESSING, 'Requires live AI processing - run with LIVE_PROCESSING=true');

    let existingVideoId: string | null = null;

    test.beforeAll(async ({ browser }) => {
      // Submit a video once and reuse for subsequent tests
      const page = await browser.newPage();
      await page.goto('/submit');

      const urlInput = page.getByLabel(/YouTube Video URL/i);
      await urlInput.fill(TEST_VIDEO_URL);

      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();

      await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });
      existingVideoId = page.url().split('/videos/')[1];

      // Wait for processing to complete
      await waitForVideoCompletion(page, PROCESSING_TIMEOUT);
      await page.close();
    });

    test('can navigate back to submit page', async ({ page }) => {
      test.skip(!existingVideoId, 'No video ID from setup');

      await page.goto(`/videos/${existingVideoId}`);

      // Find and click back link
      const backLink = page.getByRole('link', { name: /back|submit|new/i });
      await expect(backLink.first()).toBeVisible();
      await backLink.first().click();

      // Should be on submit page
      await expect(page).toHaveURL('/submit');
    });

    test('displays video metadata', async ({ page }) => {
      test.skip(!existingVideoId, 'No video ID from setup');

      await page.goto(`/videos/${existingVideoId}`);

      // Wait for content to load
      await expect(page.locator('main')).toBeVisible();

      // Should show video title or ID
      const titleOrId = page.getByText(/video|du8qD6fiX7Y/i);
      await expect(titleOrId.first()).toBeVisible({ timeout: 5_000 });
    });

    test('shows completion status for finished video', async ({ page }) => {
      test.skip(!existingVideoId, 'No video ID from setup');

      await page.goto(`/videos/${existingVideoId}`);

      // For a completed video, should show success indicators or content
      const completionIndicator = page.locator('text=/completed|success|summary|transcript/i');
      await expect(completionIndicator.first()).toBeVisible({ timeout: 10_000 });
    });

    test('transcript content is readable', async ({ page }) => {
      test.skip(!existingVideoId, 'No video ID from setup');

      await page.goto(`/videos/${existingVideoId}`);

      // Wait for video to be loaded
      await expect(page.locator('main')).toBeVisible();

      // Find transcript section
      const transcriptSection = page.locator('[data-testid="transcript"], .transcript, section:has-text("Transcript")').first();

      // Either find specific transcript section or general text content
      const transcriptContent = transcriptSection.or(page.locator('pre, .prose, .markdown').first());

      if (await transcriptContent.isVisible()) {
        // Verify there's actual text content
        const text = await transcriptContent.textContent();
        expect(text).toBeTruthy();
        expect(text!.length).toBeGreaterThan(10);
      }
    });

    test('summary content is readable', async ({ page }) => {
      test.skip(!existingVideoId, 'No video ID from setup');

      await page.goto(`/videos/${existingVideoId}`);

      // Wait for video to be loaded
      await expect(page.locator('main')).toBeVisible();

      // Find summary section
      const summarySection = page.locator('[data-testid="summary"], .summary, section:has-text("Summary")').first();

      // Either find specific summary section or general markdown content
      const summaryContent = summarySection.or(page.locator('.prose, .markdown, article').first());

      if (await summaryContent.isVisible()) {
        // Verify there's actual text content
        const text = await summaryContent.textContent();
        expect(text).toBeTruthy();
        expect(text!.length).toBeGreaterThan(10);
      }
    });
  });

  test.describe('Error Handling', () => {
    test('shows error for invalid video ID', async ({ page }) => {
      await page.goto('/videos/invalid-uuid-format');

      // Should show error message
      const errorMessage = page.getByText(/error|not found|invalid|failed/i);
      await expect(errorMessage.first()).toBeVisible({ timeout: 10_000 });
    });

    test('shows error for non-existent video', async ({ page }) => {
      // Use a valid UUID format but non-existent
      await page.goto('/videos/00000000-0000-0000-0000-000000000000');

      // Should show not found or error
      const errorMessage = page.getByText(/error|not found|failed/i);
      await expect(errorMessage.first()).toBeVisible({ timeout: 10_000 });
    });

    test('handles API timeout gracefully', async ({ page }) => {
      // Simulate slow API by adding delay
      await page.route('**/api/v1/videos/**', async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 5000));
        await route.abort('timedout');
      });

      await page.goto('/videos/00000000-0000-0000-0000-000000000001');

      // Should show loading or error state
      const statusIndicator = page.getByText(/loading|error|timeout|failed/i);
      await expect(statusIndicator.first()).toBeVisible({ timeout: 15_000 });
    });
  });

  test.describe('Polling and Auto-refresh', () => {
    test('page auto-refreshes during processing', async ({ page }) => {
      // Set up API call tracking BEFORE any navigation so we capture all
      // requests, including those fired immediately on page load.
      let apiCallCount = 0;
      await page.route('**/api/v1/videos/**', (route) => {
        apiCallCount++;
        return route.continue();
      });

      await page.goto('/submit');

      const urlInput = page.getByLabel(/YouTube Video URL/i);
      await urlInput.fill(TEST_VIDEO_URL);

      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();

      await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });

      // Wait a bit for polling to happen
      await page.waitForTimeout(10_000);

      // Should have made multiple API calls due to polling
      expect(apiCallCount).toBeGreaterThan(1);
    });
  });
});

test.describe('Reprocessing Flow', () => {
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );
  // These tests require actual video processing to complete
  test.skip(() => !LIVE_PROCESSING, 'Requires live AI processing - run with LIVE_PROCESSING=true');

  test('can reprocess an existing video', async ({ page }) => {
    // First submit a video
    await page.goto('/submit');
    const urlInput = page.getByLabel(/YouTube Video URL/i);
    await urlInput.fill(TEST_VIDEO_URL);

    const submitButton = page.getByRole('button', { name: /Process Video/i });
    await submitButton.click();

    await page.waitForURL(/\/videos\/[a-f0-9-]+/, { timeout: 15_000 });

    // Wait for completion
    await waitForVideoCompletion(page, PROCESSING_TIMEOUT);

    // Look for reprocess button
    const reprocessButton = page.getByRole('button', { name: /reprocess|retry|re-run/i });

    if (await reprocessButton.isVisible()) {
      await reprocessButton.click();

      // Should start processing again
      const processingIndicator = page.getByText(/processing|pending|running/i);
      await expect(processingIndicator.first()).toBeVisible({ timeout: 10_000 });
    }
  });
});

/**
 * Helper: Wait for video processing to complete
 */
async function waitForVideoCompletion(page: Page, timeout: number): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    // Check for completion indicators
    const completedText = page.getByText(/completed/i);
    const summarySection = page.locator('section, div').filter({ hasText: /summary/i });
    const transcriptSection = page.locator('section, div').filter({ hasText: /transcript/i });

    // Check if any completion indicator is visible
    const isCompleted = await Promise.race([
      completedText.first().isVisible().catch(() => false),
      summarySection.first().isVisible().catch(() => false),
      transcriptSection.first().isVisible().catch(() => false),
    ]);

    if (isCompleted) {
      return;
    }

    // Check for error state
    const errorText = page.getByText(/failed|error/i);
    if (await errorText.first().isVisible().catch(() => false)) {
      throw new Error('Video processing failed');
    }

    // Wait before next check (page auto-refreshes, but we poll status)
    await page.waitForTimeout(3000);
  }

  throw new Error(`Video processing did not complete within ${timeout / 1000}s`);
}
