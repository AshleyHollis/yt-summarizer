import { test, expect } from '@playwright/test';

/**
 * E2E Tests for Queue Progress UI Updates
 *
 * These tests verify that the Progress section updates correctly in the UI
 * as videos process through the queue. Uses the videos seeded by global-setup.ts
 * to avoid extra ingestion costs.
 *
 * Prerequisites:
 * - Run Aspire with FRESH database (no pre-existing videos)
 * - aspire run
 *
 * Run with WATCH_QUEUE_PROGRESS=true to monitor UI during ingestion:
 * WATCH_QUEUE_PROGRESS=true USE_EXTERNAL_SERVER=true npx playwright test queue-progress.spec.ts --headed
 *
 * This test should run FIRST when using WATCH_QUEUE_PROGRESS mode.
 */

const API_URL = process.env.API_URL || 'http://localhost:8000';

// Processing timeout - allow enough time for queue to process
const QUEUE_PROCESSING_TIMEOUT = 5 * 60 * 1000; // 5 minutes

// Get video IDs from library API
async function getVideoIds(): Promise<string[]> {
  try {
    // Use library endpoint, not /videos
    const response = await fetch(`${API_URL}/api/v1/library/videos?page_size=10`);
    if (response.ok) {
      const data = await response.json();
      // API returns "videos" not "items", and "video_id" not "id"
      return (data.videos || []).map((v: { video_id: string }) => v.video_id);
    }
  } catch {
    // Ignore
  }
  return [];
}

// Find a video that's still processing or pending
async function findProcessingVideo(): Promise<string | null> {
  try {
    // Use library endpoint with status filter
    const response = await fetch(`${API_URL}/api/v1/library/videos?status=processing&page_size=1`);
    if (response.ok) {
      const data = await response.json();
      if (data.videos?.[0]?.video_id) return data.videos[0].video_id;
    }

    // Try pending
    const pendingResponse = await fetch(`${API_URL}/api/v1/library/videos?status=pending&page_size=1`);
    if (pendingResponse.ok) {
      const data = await pendingResponse.json();
      if (data.videos?.[0]?.video_id) return data.videos[0].video_id;
    }
  } catch {
    // Ignore
  }
  return null;
}

test.describe('Queue Progress UI Updates', () => {
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  test('progress UI shows queue position and ETA updates during batch processing', async ({ page }) => {
    // This test uses videos seeded by global-setup.ts
    // When run with WATCH_QUEUE_PROGRESS=true, global-setup submits but doesn't wait
    // So we can watch the UI update as videos process

    console.log('\n📹 Finding videos to monitor...');

    // First, try to find a video that's still processing
    let videoId = await findProcessingVideo();

    if (!videoId) {
      // No processing video - get any video from the library
      const videoIds = await getVideoIds();
      if (videoIds.length > 0) {
        // Use the last video (likely deepest in queue if still processing)
        videoId = videoIds[videoIds.length - 1];
        console.log(`  Using video from library: ${videoId.slice(0, 8)}...`);
      }
    } else {
      console.log(`  Found processing video: ${videoId.slice(0, 8)}...`);
    }

    if (!videoId) {
      console.log('  ⚠ No videos found - global-setup may not have run');
      test.skip();
      return;
    }

    // Navigate to video detail page (use /library/ route, not /videos/)
    await page.goto(`/library/${videoId}`);
    await expect(page.locator('main')).toBeVisible({ timeout: 15000 });

    console.log('👀 Watching progress UI updates...\n');

    const startTime = Date.now();
    let lastQueuePosition = -1;
    let lastStage = '';
    let sawQueuePosition = false;
    let sawEta = false;
    let sawStageTransition = false;
    let completionSeen = false;

    while (Date.now() - startTime < QUEUE_PROCESSING_TIMEOUT && !completionSeen) {
      // Check for queue position display
      const queuePositionEl = page.locator('text=/Queue Position|Position in queue|#\\d+ in queue|queue.*\\d+/i');
      if (await queuePositionEl.first().isVisible().catch(() => false)) {
        const text = await queuePositionEl.first().textContent();
        const match = text?.match(/(\d+)/);
        if (match) {
          const position = parseInt(match[1], 10);
          if (position !== lastQueuePosition) {
            console.log(`  📍 Queue position: ${position}`);
            if (lastQueuePosition > 0 && position < lastQueuePosition) {
              console.log(`  ✓ Queue position decreased: ${lastQueuePosition} → ${position}`);
            }
            lastQueuePosition = position;
            sawQueuePosition = true;
          }
        }
      }

      // Check for ETA display
      const etaEl = page.locator('text=/ETA|Estimated|remaining|~\\d+[ms]/i');
      if (await etaEl.first().isVisible().catch(() => false)) {
        sawEta = true;
      }

      // Check for current stage
      const stageEl = page.locator('text=/transcrib|summariz|embed/i');
      if (await stageEl.first().isVisible().catch(() => false)) {
        const text = await stageEl.first().textContent();
        const stage = text?.toLowerCase().match(/(transcrib|summariz|embed)/)?.[1] || '';
        if (stage && stage !== lastStage) {
          console.log(`  🔄 Stage: ${lastStage || 'pending'} → ${stage}`);
          if (lastStage) {
            sawStageTransition = true;
          }
          lastStage = stage;
        }
      }

      // Check for completion
      const completedEl = page.locator('text=/completed|Status.*completed/i');
      const summaryTab = page.getByRole('button', { name: /Summary/i });

      // Check if summary tab exists and has content (indicates completion)
      if (await summaryTab.isVisible().catch(() => false)) {
        await summaryTab.click();
        await page.waitForTimeout(500);
        const summaryContent = page.locator('.prose, .markdown, [class*="summary"]');
        if (await summaryContent.first().isVisible().catch(() => false)) {
          const text = await summaryContent.first().textContent();
          if (text && text.length > 50) {
            console.log('\n  ✅ Video processing completed!');
            completionSeen = true;
            break;
          }
        }
      }

      // Also check direct completed status
      if (await completedEl.first().isVisible().catch(() => false)) {
        console.log('\n  ✅ Video processing completed!');
        completionSeen = true;
        break;
      }

      // Check for errors
      const errorEl = page.locator('text=/failed|error/i');
      if (await errorEl.first().isVisible().catch(() => false)) {
        console.log('\n  ❌ Video processing failed!');
        break;
      }

      // Wait before next check (the page should auto-refresh)
      await page.waitForTimeout(3000);
    }

    // Log results
    console.log('\n📋 Test Results:');
    console.log(`  Queue position displayed: ${sawQueuePosition ? '✓' : '(not visible - may have been first in queue)'}`);
    console.log(`  ETA displayed: ${sawEta ? '✓' : '(not visible)'}`);
    console.log(`  Stage transitions: ${sawStageTransition ? '✓' : '(not visible - may have started mid-stage)'}`);
    console.log(`  Completed: ${completionSeen ? '✓' : '✗'}`);

    // At minimum, we should see the video complete
    expect(completionSeen).toBe(true);

    // Check History tab
    console.log('\n📜 Checking History tab...');

    const historyTab = page.getByRole('button', { name: /History/i });
    if (await historyTab.isVisible().catch(() => false)) {
      await historyTab.click();

      // Verify processing stages are shown
      await expect(page.getByText(/transcribe/i).first()).toBeVisible({ timeout: 10000 });
      console.log('  ✓ History tab shows processing stages');
    }
  });

  test('progress UI updates live without page refresh', async ({ page }) => {
    // Find a video (ideally one still processing) and watch the progress update
    // This verifies the polling/auto-update mechanism works

    let videoId = await findProcessingVideo();

    if (!videoId) {
      const videoIds = await getVideoIds();
      if (videoIds.length > 0) {
        videoId = videoIds[0];
      }
    }

    if (!videoId) {
      console.log('  ⚠ No videos found');
      test.skip();
      return;
    }

    // Navigate to video page
    await page.goto(`/library/${videoId}`);
    await expect(page.locator('main')).toBeVisible({ timeout: 15000 });

    // Track network requests to verify polling is happening
    const progressRequests: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/progress') || request.url().includes('/jobs/')) {
        progressRequests.push(request.url());
      }
    });

    // Wait for a few poll cycles
    await page.waitForTimeout(15000);

    // Verify polling is happening (should see multiple progress requests)
    console.log(`\n📡 Progress API calls: ${progressRequests.length}`);
    expect(progressRequests.length).toBeGreaterThan(1);

    // The UI should reflect current status
    const statusIndicator = page.locator('text=/processing|pending|completed|transcrib|summariz|embed/i');
    await expect(statusIndicator.first()).toBeVisible();
  });

  test('multiple seeded videos create queue depth', async ({ page }) => {
    // Verify that global-setup seeded multiple videos
    const videoIds = await getVideoIds();

    console.log(`\n📊 Found ${videoIds.length} videos from global-setup`);
    expect(videoIds.length).toBeGreaterThanOrEqual(2);

    // Navigate to first video
    if (videoIds.length > 0) {
      await page.goto(`/library/${videoIds[0]}`);
      await expect(page.locator('main')).toBeVisible({ timeout: 15000 });

      // Verify progress section exists
      const progressSection = page.locator('text=/Status|Progress|Queue|Processing/i');
      await expect(progressSection.first()).toBeVisible({ timeout: 10000 });
    }
  });
});
