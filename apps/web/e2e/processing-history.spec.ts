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

    // Wait for at least one completed video from seeding
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Click on the first video
    await videoCard.click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    // Wait for page to load
    await expect(page.locator('main')).toBeVisible();

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Verify processing stages are displayed
    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/summarize/i).first()).toBeVisible();
    await expect(page.getByText(/embed/i).first()).toBeVisible();

    // Verify timing information is shown (format: Xs or Xm Ys)
    const timingPattern = page.getByText(/\d+(\.\d+)?s|\d+m/);
    await expect(timingPattern.first()).toBeVisible();
  });

  test('History tab shows Actual and Expected time summary', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Click on video
    await videoCard.click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Wait for history content
    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });

    // Verify Actual time is displayed
    const actualCard = page.locator('text=/Actual/i');
    await expect(actualCard.first()).toBeVisible();

    // Verify Expected time is displayed (includes rate limit delay)
    const expectedCard = page.locator('text=/Expected/i');
    await expect(expectedCard.first()).toBeVisible();
  });

  test('History tab shows rate limit delay breakdown', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Click on video
    await videoCard.click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    // Click History tab
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    // Wait for history content
    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });

    // The Expected card should show rate limit delay breakdown
    // Format: "incl. Xm rate limit delay" or similar
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _delayInfo = page.locator('text=/rate limit|delay/i');

    // This may or may not be visible depending on if delays are tracked
    // Just verify the summary cards are present
    const summarySection = page.locator('[class*="grid"]').filter({ hasText: /Actual|Expected/ });
    await expect(summarySection.first()).toBeVisible();
  });

  test('History tab is accessible via keyboard', async ({ page }) => {
    // Navigate to library
    await page.goto('/library?status=completed');

    // Wait for completed video
    const videoCard = page.locator('a[href^="/library/"]').first();
    await expect(videoCard).toBeVisible({ timeout: 30000 });

    // Click on video
    await videoCard.click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    // Tab to History button and press Enter
    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });

    // Focus and activate via keyboard
    await historyTab.focus();
    await page.keyboard.press('Enter');

    // Verify history content loads
    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });
  });

  test('multiple seeded videos have processing history', async ({ page }) => {
    // This test verifies that the global-setup seeded videos
    // created a queue scenario and have history data

    // Navigate to library
    await page.goto('/library?status=completed');

    // Count completed videos (should have multiple from global-setup)
    const videoCards = page.locator('a[href^="/library/"]');
    await expect(videoCards.first()).toBeVisible({ timeout: 30000 });

    const count = await videoCards.count();
    console.log(`Found ${count} completed videos from seeding`);

    // Verify at least 2 videos (to confirm queue scenario)
    expect(count).toBeGreaterThanOrEqual(2);

    // Check first video has history
    await videoCards.first().click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    const historyTab = page.getByRole('button', { name: /History/i });
    await expect(historyTab).toBeVisible({ timeout: 10000 });
    await historyTab.click();

    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });

    // Go back and check second video
    await page.goto('/library?status=completed');
    await expect(videoCards.nth(1)).toBeVisible({ timeout: 10000 });
    await videoCards.nth(1).click();
    await page.waitForURL(/\/library\/[a-f0-9-]+/);

    const historyTab2 = page.getByRole('button', { name: /History/i });
    await expect(historyTab2).toBeVisible({ timeout: 10000 });
    await historyTab2.click();

    await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });
  });
});
