/**
 * Global setup for Playwright E2E tests.
 * 
 * This runs ONCE before all tests and ensures test videos are ingested.
 * Videos are only submitted if they don't already exist (409 = skip).
 * 
 * IMPORTANT: This setup waits for videos to be FULLY PROCESSED (have segments)
 * before allowing tests to run. This ensures copilot queries have content to search.
 */

import { FullConfig } from '@playwright/test';

const API_URL = process.env.API_URL || 'http://localhost:8000';

// Test videos that E2E tests depend on
// IMPORTANT: Keep videos SHORT (<5 min) to minimize LLM token costs
// IMPORTANT: All videos MUST have YouTube auto-captions to avoid expensive Whisper transcription
// Videos are grouped by topic to test relationship detection (similarity > 0.7)
//
// To verify a video has captions, run: yt-dlp --list-subs "URL"
// Look for "Available automatic captions" in output. "has no automatic captions" = needs Whisper (expensive!)
const TEST_VIDEOS = [
  // === Push-Up Cluster (3 videos - should relate to each other) ===
  // All verified to have YouTube auto-captions
  
  // The Perfect Push Up (Calisthenicmovement) - 3:37 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=IODxDxX7oi4',
  // You CAN do pushups, my friend! (Hybrid Calisthenics) - 3:09 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=0GsVJsS6474',
  // The Perfect Push-Up (short) - 0:31 - HAS AUTO CAPTIONS  
  'https://www.youtube.com/watch?v=c-lBErfxszs',
  
  // === Kettlebell Cluster (2 videos - should relate to each other) ===
  // All verified to have YouTube auto-captions
  
  // The BEST Kettlebell Swing Tutorial - 0:58 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=aSYap2yhW8s',
  // How To Do Kettlebell Swings | Proper Form - 4:37 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=hp3qVqIHNOI',
];

// Minimum number of indexed segments required before tests can run
const MIN_SEGMENTS_REQUIRED = 30;
// Maximum wait time for video processing (5 minutes)
const MAX_WAIT_TIME_MS = 5 * 60 * 1000;
// Polling interval
const POLL_INTERVAL_MS = 10 * 1000;

async function waitForVideoProcessing(): Promise<boolean> {
  const startTime = Date.now();
  
  console.log(`[global-setup] Waiting for videos to be processed (need ${MIN_SEGMENTS_REQUIRED}+ segments)...`);
  
  while (Date.now() - startTime < MAX_WAIT_TIME_MS) {
    try {
      const coverageResponse = await fetch(`${API_URL}/api/v1/copilot/coverage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      
      if (coverageResponse.ok) {
        const coverage = await coverageResponse.json();
        const segments = coverage.segmentCount || 0;
        const elapsed = Math.round((Date.now() - startTime) / 1000);
        
        console.log(`[global-setup] Progress: ${coverage.videoCount} videos, ${segments} segments (${elapsed}s elapsed)`);
        
        if (segments >= MIN_SEGMENTS_REQUIRED) {
          console.log(`[global-setup] ✓ Ready! ${segments} segments indexed`);
          return true;
        }
      }
    } catch (error) {
      console.log(`[global-setup] Coverage check failed: ${error}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  
  console.log(`[global-setup] ⚠ Timeout waiting for video processing. Tests may fail.`);
  return false;
}

async function globalSetup(config: FullConfig) {
  // Only run when using external server (Aspire)
  if (!process.env.USE_EXTERNAL_SERVER) {
    console.log('[global-setup] Skipping video seeding (USE_EXTERNAL_SERVER not set)');
    return;
  }

  console.log('[global-setup] Seeding test videos...');
  
  let submitted = 0;
  let skipped = 0;
  let failed = 0;

  for (const url of TEST_VIDEOS) {
    try {
      const response = await fetch(`${API_URL}/api/v1/videos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`  ✓ Submitted: ${data.title || url}`);
        submitted++;
      } else if (response.status === 409) {
        console.log(`  ⊘ Already exists: ${url}`);
        skipped++;
      } else {
        console.log(`  ✗ Failed (${response.status}): ${url}`);
        failed++;
      }
    } catch (error) {
      console.log(`  ✗ Error: ${url} - ${error}`);
      failed++;
    }
  }

  console.log(`[global-setup] Done: ${submitted} submitted, ${skipped} skipped, ${failed} failed`);

  // Wait for videos to be fully processed before running tests
  // This is critical - copilot queries need indexed segments to work
  await waitForVideoProcessing();
}

export default globalSetup;
