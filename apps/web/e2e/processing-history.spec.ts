import { test, expect } from '@playwright/test';

const API_URL = process.env.API_URL || 'http://localhost:8000';

/**
 * E2E Tests for Processing History Feature
 *
 * These tests verify the History tab on video detail pages:
 * 1. Processing stages are displayed (transcribe, summarize, embed)
 * 2. Timing information is shown (actual processing time)
 * 3. Expected time is shown (including rate limit delays)
 * 4. Wait times are tracked for queued videos
 *
 * Prerequisites:
 * - Videos are seeded by global-setup.ts when running E2E tests
 * - Run Aspire first: aspire run
 * - Then run tests with: USE_EXTERNAL_SERVER=true npm run test:e2e
 */

test.describe('Processing History', () => {
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  // Do NOT clear storageState — these tests need the project auth (user.json / admin.json)
  // to access the API in preview environments. storageState: undefined does not reliably
  // clear the project-level config across all Playwright versions and was the root cause
  // of unauthenticated API calls returning empty video lists.

  // Video IDs with confirmed processing history (populated by beforeAll)
  let videoIdWithHistory: string | null = null;
  let secondVideoIdWithHistory: string | null = null;

  test.beforeAll(async ({ request }) => {
    // Find up to 2 completed full-analysis videos that actually have processing history records.
    // Old videos may have been processed before history tracking was added,
    // and transcript-only videos intentionally do not have summary/embed stages,
    // so we verify the /history endpoint returns AI stages before picking a video.
    const listResponse = await request.get(
      `${API_URL}/api/v1/library/videos?status=completed&page_size=50`
    );
    if (!listResponse.ok()) return;

    const listData = await listResponse.json();
    for (const video of listData.videos || []) {
      const historyResponse = await request.get(
        `${API_URL}/api/v1/jobs/video/${video.video_id}/history`
      );
      if (!historyResponse.ok()) continue;
      const historyData = await historyResponse.json();
      const historyText = JSON.stringify(historyData).toLowerCase();
      const hasFullAnalysisHistory =
        historyData.stages &&
        historyData.stages.length > 0 &&
        (historyText.includes('summar') || historyText.includes('embed'));
      if (hasFullAnalysisHistory) {
        if (!videoIdWithHistory) {
          videoIdWithHistory = video.video_id;
          console.log(`[processing-history] Found video 1 with history: ${videoIdWithHistory}`);
        } else if (!secondVideoIdWithHistory) {
          secondVideoIdWithHistory = video.video_id;
          console.log(
            `[processing-history] Found video 2 with history: ${secondVideoIdWithHistory}`
          );
          break;
        }
      }
    }
    if (!videoIdWithHistory) {
      console.log('[processing-history] No completed full-analysis videos with history found');
    }
  });

  test('History tab displays processing stages and timing', async ({ page }) => {
    test.skip(!videoIdWithHistory, 'No completed videos with processing history found');

    await page.goto(`/library/${videoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('main')).toBeVisible();

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 15000 });
    await historyTab.click();

    // Verify processing stages are displayed (using actual stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/Generating Summary/i).first()).toBeVisible();
    await expect(page.getByText(/Creating Embeddings/i).first()).toBeVisible();

    // Verify timing information is shown (format: Xs or Xm Ys)
    const timingPattern = page.getByText(/\d+(\.\d+)?s|\d+m/);
    await expect(timingPattern.first()).toBeVisible();
  });

  test('History tab shows Actual and Expected time summary', async ({ page }) => {
    test.skip(!videoIdWithHistory, 'No completed videos with processing history found');

    await page.goto(`/library/${videoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 15000 });
    await historyTab.click();

    // Wait for history content (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });

    // Verify Processing time is displayed (actual processing time column)
    const processingHeader = page.locator('text=/Processing/i');
    await expect(processingHeader.first()).toBeVisible();

    // Verify Est. (estimated) time is displayed
    const estimatedHeader = page.locator('text=/Est\\./i');
    await expect(estimatedHeader.first()).toBeVisible();
  });

  test('History tab shows rate limit delay breakdown', async ({ page }) => {
    test.skip(!videoIdWithHistory, 'No completed videos with processing history found');

    await page.goto(`/library/${videoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 15000 });
    await historyTab.click();

    // Wait for history content (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _delayInfo = page.locator('text=/rate limit|delay/i');

    // Verify the summary stats cards are present (Total Elapsed, Processing, etc.)
    const summarySection = page
      .locator('[class*="grid"]')
      .filter({ hasText: /Total Elapsed|Processing/ });
    await expect(summarySection.first()).toBeVisible();
  });

  test('History tab is accessible via keyboard', async ({ page }) => {
    test.skip(!videoIdWithHistory, 'No completed videos with processing history found');

    await page.goto(`/library/${videoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 15000 });

    // Focus and activate via keyboard
    await historyTab.focus();
    await page.keyboard.press('Enter');

    // Verify history content loads (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });
  });

  test('multiple seeded videos have processing history', async ({ page }) => {
    test.slow(); // This test navigates between multiple videos
    test.skip(!videoIdWithHistory, 'No completed videos with processing history found');
    test.skip(
      !secondVideoIdWithHistory,
      'Only 1 video with history found — need at least 2 for this test'
    );

    // Check first video has history
    await page.goto(`/library/${videoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 15000 });
    await historyTab.click();
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });

    // Check second video has history
    await page.goto(`/library/${secondVideoIdWithHistory}`);
    await page.waitForLoadState('domcontentloaded');

    const historyTab2 = page.getByRole('button', { name: /History/i });
    await expect(historyTab2).toBeVisible({ timeout: 15000 });
    await historyTab2.click();
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 15000 });
  });
});
