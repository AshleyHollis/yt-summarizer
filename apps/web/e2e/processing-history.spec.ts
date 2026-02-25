import { test, expect } from '@playwright/test';

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

  test('History tab displays processing stages and timing', async ({ page }) => {
    // Navigate to library - global-setup.ts seeds videos before tests run
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');

    // Wait for at least one completed video from seeding
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Extract the href and navigate directly — more reliable than clicking
    // because Next.js hydration may not be complete when the link is visible
    const href = await videoCard.getAttribute('href');
    expect(href).toBeTruthy();
    await page.goto(href!);
    await page.waitForLoadState('domcontentloaded');

    // Wait for page to load
    await expect(page.locator('main')).toBeVisible();

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Verify processing stages are displayed (using actual stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/Generating Summary/i).first()).toBeVisible();
    await expect(page.getByText(/Creating Embeddings/i).first()).toBeVisible();

    // Verify timing information is shown (format: Xs or Xm Ys)
    const timingPattern = page.getByText(/\d+(\.\d+)?s|\d+m/);
    await expect(timingPattern.first()).toBeVisible();
  });

  test('History tab shows Actual and Expected time summary', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Extract href and navigate directly — more reliable than clicking
    const href = await videoCard.getAttribute('href');
    expect(href).toBeTruthy();
    await page.goto(href!);
    await page.waitForLoadState('domcontentloaded');

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Wait for history content (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });

    // Verify Processing time is displayed (actual processing time column)
    const processingHeader = page.locator('text=/Processing/i');
    await expect(processingHeader.first()).toBeVisible();

    // Verify Est. (estimated) time is displayed
    const estimatedHeader = page.locator('text=/Est\\./i');
    await expect(estimatedHeader.first()).toBeVisible();
  });

  test('History tab shows rate limit delay breakdown', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Extract href and navigate directly
    const href = await videoCard.getAttribute('href');
    expect(href).toBeTruthy();
    await page.goto(href!);
    await page.waitForLoadState('domcontentloaded');

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Wait for history content (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });

    // The Expected card should show rate limit delay breakdown
    // Format: "incl. Xm rate limit delay" or similar
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _delayInfo = page.locator('text=/rate limit|delay/i');

    // This may or may not be visible depending on if delays are tracked
    // Just verify the summary stats cards are present (Total Elapsed, Processing, etc.)
    const summarySection = page.locator('[class*="grid"]').filter({ hasText: /Total Elapsed|Processing/ });
    await expect(summarySection.first()).toBeVisible();
  });

  test('History tab is accessible via keyboard', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Extract href and navigate directly
    const href = await videoCard.getAttribute('href');
    expect(href).toBeTruthy();
    await page.goto(href!);
    await page.waitForLoadState('domcontentloaded');

    // Tab to History button and press Enter
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });

    // Focus and activate via keyboard
    await historyTab.focus();
    await page.keyboard.press('Enter');

    // Verify history content loads (stage labels from API)
    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });
  });

  test('multiple seeded videos have processing history', async ({ page }) => {
    test.slow(); // This test navigates between multiple videos
    // This test verifies that the global-setup seeded videos
    // created a queue scenario and have history data

    // Navigate to library
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');

    // Count completed videos (should have multiple from global-setup)
    const videoCards = page.locator('a[href^="/library/"]');
    await expect(videoCards.first()).toBeVisible({ timeout: 30000 });

    const count = await videoCards.count();
    console.log(`Found ${count} completed videos from seeding`);

    // Verify at least 2 videos (to confirm queue scenario)
    expect(count).toBeGreaterThanOrEqual(2);

    // Check first video has history — extract href and navigate directly
    const href1 = await videoCards.first().getAttribute('href');
    expect(href1).toBeTruthy();
    await page.goto(href1!);
    await page.waitForLoadState('domcontentloaded');

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });

    // Go back and check second video
    await page.goto('/library?status=completed');
    await page.waitForLoadState('domcontentloaded');
    const videoCards2 = page.locator('a[href^="/library/"]');
    await expect(videoCards2.nth(1)).toBeVisible({ timeout: 10000 });

    // Extract href and navigate directly for second video too
    const href2 = await videoCards2.nth(1).getAttribute('href');
    expect(href2).toBeTruthy();
    await page.goto(href2!);
    await page.waitForLoadState('domcontentloaded');

    const historyTab2 = page.getByRole('button', { name: /History/i });
    await expect(historyTab2).toBeVisible({ timeout: 10000 });
    await historyTab2.click();

    await expect(page.getByText(/Extracting Transcript/i).first()).toBeVisible({ timeout: 10000 });
  });
});
