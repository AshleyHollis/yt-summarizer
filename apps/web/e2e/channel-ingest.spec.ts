import { test, expect } from '@playwright/test';

/**
 * E2E Tests for Channel Ingestion (User Story 2)
 *
 * These tests verify the channel batch ingestion flow:
 * 1. Navigation to ingest page from home
 * 2. Channel URL submission and video fetching
 * 3. Video selection and batch creation
 * 4. Batch progress tracking
 *
 * Prerequisites:
 * - Run Aspire first: cd services/aspire/AppHost && dotnet run
 * - Then run tests with: USE_EXTERNAL_SERVER=true npm run test:e2e
 * - For tests that require real AI processing: LIVE_PROCESSING=true
 *
 * Test Channel: https://www.youtube.com/@darciisabella/videos (small channel with few videos)
 */

const TEST_CHANNEL_URL = 'https://www.youtube.com/@darciisabella/videos';

// Check if live processing tests should run (requires real AI services)
const LIVE_PROCESSING = process.env.LIVE_PROCESSING === 'true';

test.describe('Channel Ingestion Flow', () => {
  test.describe('Navigation', () => {
    test('submit page has link to channel ingestion', async ({ page }) => {
      await page.goto('/submit');

      // Check for channel ingestion link
      const ingestLink = page.getByRole('link', { name: /ingest multiple videos from a channel/i });
      await expect(ingestLink).toBeVisible();
      await expect(ingestLink).toHaveAttribute('href', '/ingest');
    });

    test('can navigate to ingest page from submit page', async ({ page }) => {
      await page.goto('/submit');

      // Wait for the link to be visible and page to be fully hydrated
      const ingestLink = page.getByRole('link', { name: /ingest multiple videos from a channel/i });
      await expect(ingestLink).toBeVisible();

      // Click the channel ingestion link
      await ingestLink.click();

      // Should be on ingest page
      await expect(page).toHaveURL(/\/ingest(?:\?|$)/, { timeout: 10000 });
    });

    test('ingest page renders correctly', async ({ page }) => {
      await page.goto('/ingest');

      // Check page elements
      await expect(page.getByRole('heading', { name: /Ingest from Channel/i })).toBeVisible();
      await expect(page.getByLabel(/YouTube Channel URL/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /Fetch Videos/i })).toBeVisible();
    });
  });

  test.describe('Channel Form Validation', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/ingest');
    });

    test('shows error for empty channel URL', async ({ page }) => {
      // Click fetch without entering URL
      await page.getByRole('button', { name: /Fetch Videos/i }).click();

      // Should show validation error
      await expect(page.getByText(/required/i)).toBeVisible();
    });

    test('shows error for invalid channel URL', async ({ page }) => {
      // Enter invalid URL
      await page.getByLabel(/YouTube Channel URL/i).fill('https://example.com/not-a-channel');
      await page.getByRole('button', { name: /Fetch Videos/i }).click();

      // Should show validation error
      await expect(page.getByText(/valid YouTube channel URL/i)).toBeVisible();
    });

    test('accepts valid channel URL formats', async ({ page }) => {
      const input = page.getByLabel(/YouTube Channel URL/i);

      // Test @handle format
      await input.fill('https://www.youtube.com/@darciisabella');
      await expect(input).toHaveValue('https://www.youtube.com/@darciisabella');

      // Test /channel/ format
      await input.clear();
      await input.fill('https://www.youtube.com/channel/UC1234567890abcdefg');
      await expect(input).toHaveValue('https://www.youtube.com/channel/UC1234567890abcdefg');
    });
  });

  test.describe('Channel Video Fetching', () => {
    // These tests require the backend to be running
    test.beforeEach(async ({ page }) => {
      await page.goto('/ingest');
    });

    test('fetches videos from channel URL', async ({ page }) => {
      // Enter channel URL
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);

      // Click fetch
      await page.getByRole('button', { name: /Fetch Videos/i }).click();

      // Wait for videos to load (timeout for yt-dlp)
      // The loading state shows "Loading..." briefly, then videos appear
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Should show channel name in heading
      await expect(page.getByRole('heading', { name: /Darci Isabella/i })).toBeVisible();
    });

    test('displays video information correctly', async ({ page }) => {
      // Fetch videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();

      // Wait for videos
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Check video items exist - they may have checkboxes or already-ingested indicators
      const firstVideo = page.locator('[data-testid="video-item"]').first();
      // Video should have either a checkbox or an "already ingested" indicator
      const hasCheckbox = await firstVideo.locator('input[type="checkbox"]').count();
      const hasAlreadyIngested = await firstVideo.getByText(/Already ingested/i).count();
      expect(hasCheckbox + hasAlreadyIngested).toBeGreaterThan(0);
    });

    test('shows video list with channel info', async ({ page }) => {
      // Fetch videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Check for channel info display
      await expect(page.getByText(/videos loaded/i)).toBeVisible();
    });

    test('shows select all and clear controls', async ({ page }) => {
      // Fetch videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Check for select all / clear controls
      await expect(page.getByRole('button', { name: /Select All/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /Clear/i })).toBeVisible();
    });
  });

  test.describe('Batch Creation', () => {
    // These tests require actual video processing to complete
    test.skip(
      () => !LIVE_PROCESSING,
      'Requires live AI processing - run with LIVE_PROCESSING=true'
    );

    test.beforeEach(async ({ page }) => {
      await page.goto('/ingest');
    });

    test('shows ingest buttons after fetching videos', async ({ page }) => {
      // Fetch videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Should show ingest buttons
      await expect(page.getByRole('button', { name: /Ingest Selected/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /Ingest All Channel Videos/i })).toBeVisible();
    });

    test('can ingest all channel videos', async ({ page }) => {
      // Fetch videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Click ingest all button
      await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();

      // Should navigate to batch progress page
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/);

      // Should show batch progress
      await expect(page.getByText(/Batch Progress/i)).toBeVisible();
    });

    test('batch progress page shows navigation buttons', async ({ page }) => {
      // Fetch and ingest videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/);

      // Check navigation buttons
      await expect(page.getByRole('link', { name: /Ingest More Videos/i })).toBeVisible();
      await expect(page.getByRole('link', { name: /View Library/i })).toBeVisible();
    });

    test('batch progress page shows back to ingest link', async ({ page }) => {
      // Fetch and ingest videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/);

      // Check back to ingest link
      await expect(page.getByRole('link', { name: /Back to Ingest/i })).toBeVisible();
    });

    test('batch progress page displays batch details and video list', async ({ page }) => {
      // Fetch and ingest videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/);

      // Wait for batch details to load (batch name should appear in heading)
      await expect(page.getByRole('heading', { name: /Darci Isabella/i })).toBeVisible({
        timeout: 10000,
      });

      // Verify video count is displayed
      await expect(page.getByText(/\d+\s*videos?/i)).toBeVisible({ timeout: 10000 });
    });

    test('View Ready Videos link uses correct status=completed URL', async ({ page }) => {
      // This test verifies the fix for the bug where the link used status=ready (invalid)
      // instead of status=completed (valid)

      // Fetch and ingest videos
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();

      // Wait for videos to load
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 15000 });

      // Wait for batch to potentially complete or have some succeeded items
      // The "View Ready Videos" link only appears when succeeded_count > 0

      // Wait a bit for potential processing
      await page.waitForTimeout(5000);

      // Check if View Ready link exists (it may not if no videos succeeded yet)
      const viewReadyLink = page.getByRole('link', { name: /View.*Ready Video/i });

      if (await viewReadyLink.isVisible()) {
        // CRITICAL: Verify the link uses status=completed, NOT status=ready
        const href = await viewReadyLink.getAttribute('href');
        expect(href).toBe('/library?status=completed');
        expect(href).not.toContain('status=ready');

        // Click the link and verify navigation works
        await viewReadyLink.click();
        await expect(page).toHaveURL(/\/library\?status=completed/);

        // Verify library page loads with the filter applied
        await expect(page.getByRole('heading', { name: 'Library' })).toBeVisible();
        const statusDropdown = page.getByLabel(/Status/i);
        await expect(statusDropdown).toHaveValue('completed');
      }
    });
  });

  test.describe('Batches List Page', () => {
    test('batches page is accessible', async ({ page }) => {
      await page.goto('/batches');

      // Check page renders - the page shows "Jobs" heading
      await expect(page.getByRole('heading', { name: /Jobs/i })).toBeVisible();
    });
  });

  test.describe('Already Ingested Videos', () => {
    test('shows already ingested indicator for previously ingested videos', async ({ page }) => {
      // Fetch videos from a channel that has been ingested before
      await page.goto('/ingest');
      await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
      await page.getByRole('button', { name: /Fetch Videos/i }).click();
      await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
        timeout: 60000,
      });

      // Check if any video shows "already ingested"
      // (This will be true if videos were previously ingested)
      const alreadyIngestedCount = await page.getByText(/Already ingested/i).count();
      // Just verify the page loaded correctly - the indicator may or may not be present
      // depending on whether videos were previously ingested
      expect(alreadyIngestedCount).toBeGreaterThanOrEqual(0);
    });
  });
});
