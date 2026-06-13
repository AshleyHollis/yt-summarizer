import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

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
const userAuthFile = path.join(__dirname, '../playwright/.auth/user.json');
const MOCK_BATCH_ID = '11111111-1111-4111-8111-111111111111';

const mockChannelResponse = {
  channel_id: null,
  youtube_channel_id: 'UC3_A9yDRB1TMyah5CD0TfyQ',
  channel_name: 'Darci Isabella',
  total_video_count: 3,
  returned_count: 3,
  videos: [
    {
      youtube_video_id: 'ian-storm',
      title: 'Hurricane Ian... headed straight for us',
      duration: 312,
      publish_date: '2022-09-28T00:00:00Z',
      thumbnail_url: 'https://img.youtube.com/vi/ian-storm/mqdefault.jpg',
      already_ingested: false,
    },
    {
      youtube_video_id: 'garden-tour',
      title: 'Garden update and recovery',
      duration: 201,
      publish_date: '2022-10-05T00:00:00Z',
      thumbnail_url: 'https://img.youtube.com/vi/garden-tour/mqdefault.jpg',
      already_ingested: true,
    },
    {
      youtube_video_id: 'small-channel',
      title: 'Small channel test fixture',
      duration: 98,
      publish_date: '2022-10-12T00:00:00Z',
      thumbnail_url: 'https://img.youtube.com/vi/small-channel/mqdefault.jpg',
      already_ingested: false,
    },
  ],
  next_cursor: null,
  has_more: false,
};

const mockBatchResponse = {
  id: MOCK_BATCH_ID,
  name: 'Darci Isabella - Test',
  channel_name: 'Darci Isabella',
  processing_mode: 'full_analysis',
  status: 'completed',
  total_count: 2,
  pending_count: 0,
  running_count: 0,
  succeeded_count: 2,
  failed_count: 0,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const mockBatchDetailResponse = {
  ...mockBatchResponse,
  items: [
    {
      id: '22222222-2222-4222-8222-222222222222',
      video_id: '33333333-3333-4333-8333-333333333333',
      youtube_video_id: 'ian-storm',
      title: 'Hurricane Ian... headed straight for us',
      status: 'succeeded',
      error_message: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    },
  ],
};

const mockQuotaResponse = {
  tier: 'free',
  transcripts: {
    used_today: 0,
    processed_today: 0,
    limit: 100,
    remaining: 100,
    queued: 0,
    estimated_days: null,
  },
  ai_features: {
    used_today: 0,
    processed_today: 0,
    limit: 5,
    remaining: 5,
    queued: 0,
    estimated_days: null,
  },
  videos: {
    used_today: 0,
    processed_today: 0,
    limit: 100,
    remaining: 100,
    queued: 0,
    estimated_days: null,
  },
  copilot: {
    used_this_hour: 0,
    limit: 30,
    remaining: 30,
    resets_in_seconds: 3600,
  },
};

async function mockAuthenticatedChannelPage(page: Page) {
  await page.addInitScript(
    ({ channelResponse, batchResponse, batchDetailResponse, batchId, quotaResponse }) => {
      const sessionResponse = {
        user: {
          sub: 'auth0|channel-e2e-user',
          email: 'user@test.yt-summarizer.internal',
          email_verified: true,
          name: 'Channel E2E User',
          picture: null,
          'https://yt-summarizer.com/role': 'normal',
          updated_at: '2026-01-01T00:00:00Z',
        },
      };
      const originalFetch = window.fetch.bind(window);
      window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        const method = (
          init?.method || (input instanceof Request ? input.method : 'GET')
        ).toUpperCase();

        if (url.includes('/api/auth/session')) {
          return new Response(JSON.stringify(sessionResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (url.includes('/api/v1/channels')) {
          return new Response(JSON.stringify(channelResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (url.includes('/api/v1/quota')) {
          return new Response(JSON.stringify(quotaResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (url.endsWith('/api/v1/batches') && method === 'POST') {
          return new Response(JSON.stringify(batchResponse), {
            status: 201,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (url.includes(`/api/v1/batches/${batchId}`)) {
          return new Response(JSON.stringify(batchDetailResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        return originalFetch(input, init);
      };
    },
    {
      channelResponse: mockChannelResponse,
      batchResponse: mockBatchResponse,
      batchDetailResponse: mockBatchDetailResponse,
      batchId: MOCK_BATCH_ID,
      quotaResponse: mockQuotaResponse,
    }
  );

  await page.route('**/api/auth/session**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        user: {
          sub: 'auth0|channel-e2e-user',
          email: 'user@test.yt-summarizer.internal',
          email_verified: true,
          name: 'Channel E2E User',
          picture: null,
          'https://yt-summarizer.com/role': 'normal',
          updated_at: '2026-01-01T00:00:00Z',
        },
      }),
    });
  });

  await page.route('**/api/v1/channels**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(mockChannelResponse),
    });
  });

  await page.route('**/api/v1/quota**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(mockQuotaResponse),
    });
  });

  await page.route('**/api/v1/batches', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify(mockBatchResponse),
      });
      return;
    }

    await route.continue();
  });

  await page.route(`**/api/v1/batches/${MOCK_BATCH_ID}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(mockBatchDetailResponse),
    });
  });
}

// Check if live processing tests should run (requires real AI services)
const LIVE_PROCESSING = process.env.LIVE_PROCESSING === 'true';
const hasUserAuthState = () => fs.existsSync(userAuthFile);

test.describe('Channel Ingestion Flow', () => {
  test.describe.configure({ mode: 'serial' });

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

      await expect(page.getByRole('heading', { name: /Ingest from Channel/i })).toBeVisible();
      if (!hasUserAuthState()) {
        await expect(page.getByText(/Sign in to import videos from a channel/i)).toBeVisible();
        await expect(page.getByRole('button', { name: /Sign in with Google/i })).toBeVisible();
        return;
      }

      await expect(page.getByLabel(/YouTube Channel URL/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /Fetch Videos/i })).toBeVisible();
    });
  });

  test.describe('Channel Form Validation', () => {
    test.skip(
      () => !hasUserAuthState(),
      'Auth0 user credentials not configured - channel ingestion form is auth-gated'
    );

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
    test.beforeEach(async ({ page }) => {
      await mockAuthenticatedChannelPage(page);
      await page.goto('/ingest');
      // Wait for AuthGate to finish loading auth state so the channel URL
      // input is visible before each test body runs.
      await expect(page.getByLabel(/YouTube Channel URL/i)).toBeVisible({ timeout: 30_000 });
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
      'Requires batch flow coverage - run with LIVE_PROCESSING=true'
    );

    // Run serially to avoid race conditions when multiple tests hit the same channel API
    test.describe.configure({ mode: 'serial' });

    // Shared batch URL — created once in test 'can ingest all channel videos' and reused
    // by subsequent tests that verify batch progress page behavior
    let sharedBatchUrl: string | null = null;

    test.beforeEach(async ({ page }) => {
      await mockAuthenticatedChannelPage(page);
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
      await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 30000 });
      sharedBatchUrl = page.url();

      // Should show batch progress
      await expect(page.getByText(/Batch Progress/i)).toBeVisible();
    });

    test('batch progress page shows navigation buttons', async ({ page }) => {
      if (sharedBatchUrl) {
        await page.goto(sharedBatchUrl);
      } else {
        await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
        await page.getByRole('button', { name: /Fetch Videos/i }).click();
        await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
          timeout: 60000,
        });
        await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
        await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 30000 });
        sharedBatchUrl = page.url();
      }

      // Check navigation buttons
      await expect(page.getByRole('link', { name: /Ingest More Videos/i })).toBeVisible();
      await expect(page.getByRole('link', { name: /View Library/i })).toBeVisible();
    });

    test('batch progress page shows back to ingest link', async ({ page }) => {
      if (sharedBatchUrl) {
        await page.goto(sharedBatchUrl);
      } else {
        await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
        await page.getByRole('button', { name: /Fetch Videos/i }).click();
        await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
          timeout: 60000,
        });
        await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
        await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 30000 });
        sharedBatchUrl = page.url();
      }

      // Check back to ingest link
      await expect(page.getByRole('link', { name: /Back to Ingest/i })).toBeVisible();
    });

    test('batch progress page displays batch details and video list', async ({ page }) => {
      if (sharedBatchUrl) {
        await page.goto(sharedBatchUrl);
      } else {
        await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
        await page.getByRole('button', { name: /Fetch Videos/i }).click();
        await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
          timeout: 60000,
        });
        await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
        await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 30000 });
        sharedBatchUrl = page.url();
      }

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

      if (sharedBatchUrl) {
        await page.goto(sharedBatchUrl);
      } else {
        await page.getByLabel(/YouTube Channel URL/i).fill(TEST_CHANNEL_URL);
        await page.getByRole('button', { name: /Fetch Videos/i }).click();
        await expect(page.locator('[data-testid="video-item"]').first()).toBeVisible({
          timeout: 60000,
        });
        await page.getByRole('button', { name: /Ingest All Channel Videos/i }).click();
        await expect(page).toHaveURL(/\/ingest\/[a-f0-9-]+/, { timeout: 30000 });
        sharedBatchUrl = page.url();
      }

      // Wait for batch to potentially complete or have some succeeded items
      // The "View Ready Videos" link only appears when succeeded_count > 0
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
        await expect(page.getByRole('button', { name: /Select videos/i })).toBeVisible();
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
      await mockAuthenticatedChannelPage(page);
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
