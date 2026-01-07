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
// IMPORTANT: Keep videos SHORT where possible to minimize LLM token costs
// IMPORTANT: All videos MUST have YouTube auto-captions to avoid expensive Whisper transcription
// Videos are grouped by topic to test relationship detection (similarity > 0.7)
//
// To verify a video has captions, run: yt-dlp --list-subs "URL"
// Look for "Available automatic captions" in output. "has no automatic captions" = needs Whisper (expensive!)
const TEST_VIDEOS = [
  // === Python OOP Series (Corey Schafer) - Primary Learning Path Test Videos ===
  // These videos form a clear pedagogical progression for testing learning path ordering
  // All verified to have YouTube auto-captions
  
  // Python OOP Tutorial 1: Classes and Instances - 15:28 - BEGINNER
  'https://www.youtube.com/watch?v=ZDa-Z5JzLYM',
  // Python OOP Tutorial 2: Class Variables - ~12 min - BEGINNER  
  'https://www.youtube.com/watch?v=BJ-VvGyQxho',
  // Python OOP Tutorial 3: classmethods and staticmethods - ~15 min - INTERMEDIATE
  'https://www.youtube.com/watch?v=rq8cL2XMM5M',
  // Python OOP Tutorial 4: Inheritance - 19:40 - INTERMEDIATE
  'https://www.youtube.com/watch?v=RSl87lqOXDE',
  // Python OOP Tutorial 5: Special (Magic/Dunder) Methods - 13:50 - ADVANCED
  'https://www.youtube.com/watch?v=3ohzBxoFHAY',
  // Python OOP Tutorial 6: Property Decorators - ~10 min - ADVANCED
  'https://www.youtube.com/watch?v=jCzT9XFZ5bw',
  
  // === JavaScript Async Series - IMPLICIT ORDER Test Videos ===
  // NO explicit ordering in titles - tests LLM's ability to infer correct order from content
  // All verified to have YouTube auto-captions
  
  // JavaScript in 100 Seconds (Fireship) - 2:36 - language overview
  'https://www.youtube.com/watch?v=DHjqpvDnNGE',
  // What is a callback? - 4:46 - fundamental async pattern
  'https://www.youtube.com/watch?v=xHneyv38Jro',
  // JavaScript Promise in 100 Seconds (Fireship) - 1:39 - solves callback hell
  'https://www.youtube.com/watch?v=RvYYCGs45L4',
  // JavaScript Async Await - 7:31 - syntactic sugar for promises
  'https://www.youtube.com/watch?v=V_Kr9OSfDeU',
  // Closures Explained in 100 Seconds (Fireship) - 4:57 - advanced function concept
  'https://www.youtube.com/watch?v=vKJpN5FAeF4',
  
  // === Fitness Videos (for general copilot testing, relationship detection) ===
  // Kept shorter videos for cost-effective general testing
  
  // The Perfect Push Up (Calisthenicmovement) - 3:37 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=IODxDxX7oi4',
  // You CAN do pushups, my friend! (Hybrid Calisthenics) - 3:09 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=0GsVJsS6474',
  
  // === Kettlebell Cluster (2 videos - should relate to each other) ===
  // All verified to have YouTube auto-captions
  
  // The BEST Kettlebell Swing Tutorial - 0:58 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=aSYap2yhW8s',
  // How To Do Kettlebell Swings | Proper Form - 4:37 - HAS AUTO CAPTIONS
  'https://www.youtube.com/watch?v=hp3qVqIHNOI',
];

// === ORDERING VERIFICATION VIDEOS ===
// These videos have explicit difficulty levels in their titles/content and represent
// a known correct pedagogical order verified by humans. Used to test that the LLM
// correctly orders videos from beginner → intermediate → advanced.
//
// TOPIC: Python Object-Oriented Programming (Corey Schafer's OOP Tutorial Series)
// Why this series is ideal for testing:
// 1. Single creator = consistent teaching style and terminology
// 2. Explicitly numbered series (1-6) with clear progression
// 3. Same "Employee" class example throughout all tutorials
// 4. Popular/validated - millions of views, heavily referenced in Python learning communities
// 5. Clear pedagogical structure: concepts build on each other
//
// IMPORTANT: Videos are 10-20 minutes each. While longer than ideal, the clear
// pedagogical structure makes them excellent for validating learning path ordering.
// All verified to have YouTube auto-captions.
//
// EXPECTED ORDER for learning path tests (numbered series from the creator):
// 1. BEGINNER: Classes and Instances (foundation - what is a class/object)
// 2. BEGINNER: Class Variables (builds on #1 - shared vs instance state)
// 3. INTERMEDIATE: classmethods and staticmethods (introduces decorators)
// 4. INTERMEDIATE: Inheritance (core OOP concept requiring 1-3 foundation)
// 5. ADVANCED: Special (Magic/Dunder) Methods (Python-specific advanced features)
// 6. ADVANCED: Property Decorators (encapsulation, final refinement of class design)
export const ORDERED_TEST_VIDEOS = {
  // Video IDs with their expected position in a learning path
  // Tests can verify the LLM returns these in the correct order
  pythonOOP: {
    description: 'Python OOP tutorial series with explicit numbered progression (Corey Schafer)',
    expectedOrder: [
      {
        id: 'ZDa-Z5JzLYM',
        url: 'https://www.youtube.com/watch?v=ZDa-Z5JzLYM',
        title: 'Python OOP Tutorial 1: Classes and Instances',
        level: 'beginner',
        duration: 928, // 15:28
        // Content signals: "Tutorial 1", introduces basic class syntax, Employee class example
      },
      {
        id: 'BJ-VvGyQxho',
        url: 'https://www.youtube.com/watch?v=BJ-VvGyQxho',
        title: 'Python OOP Tutorial 2: Class Variables',
        level: 'beginner',
        duration: 730, // ~12 min
        // Content signals: "Tutorial 2", class vs instance variables, shared state
      },
      {
        id: 'rq8cL2XMM5M',
        url: 'https://www.youtube.com/watch?v=rq8cL2XMM5M',
        title: 'Python OOP Tutorial 3: classmethods and staticmethods',
        level: 'intermediate',
        duration: 900, // ~15 min
        // Content signals: "Tutorial 3", @classmethod, @staticmethod decorators, alternative constructors
      },
      {
        id: 'RSl87lqOXDE',
        url: 'https://www.youtube.com/watch?v=RSl87lqOXDE',
        title: 'Python OOP Tutorial 4: Inheritance - Creating Subclasses',
        level: 'intermediate',
        duration: 1180, // 19:40
        // Content signals: "Tutorial 4", inheritance, super(), DRY principle
      },
      {
        id: '3ohzBxoFHAY',
        url: 'https://www.youtube.com/watch?v=3ohzBxoFHAY',
        title: 'Python OOP Tutorial 5: Special (Magic/Dunder) Methods',
        level: 'advanced',
        duration: 830, // 13:50
        // Content signals: "Tutorial 5", __init__, __repr__, __str__, operator overloading
      },
      {
        id: 'jCzT9XFZ5bw',
        url: 'https://www.youtube.com/watch?v=jCzT9XFZ5bw',
        title: 'Python OOP Tutorial 6: Property Decorators - Getters, Setters, and Deleters',
        level: 'advanced',
        duration: 610, // ~10 min
        // Content signals: "Tutorial 6", @property, encapsulation, final series video
      },
    ],
  },
  // Legacy fitness videos - kept for backwards compatibility with existing tests
  fitness: {
    description: 'Fitness videos for general copilot testing (not for ordering verification)',
    videos: [
      {
        id: 'IODxDxX7oi4',
        url: 'https://www.youtube.com/watch?v=IODxDxX7oi4',
        title: 'The Perfect Push Up (Calisthenicmovement)',
        duration: 217, // 3:37
      },
      {
        id: '0GsVJsS6474',
        url: 'https://www.youtube.com/watch?v=0GsVJsS6474',
        title: 'You CAN do pushups, my friend! (Hybrid Calisthenics)',
        duration: 189, // 3:09
      },
    ],
  },
};

// === IMPLICIT ORDERING VERIFICATION VIDEOS ===
// These videos test the LLM's ability to infer correct pedagogical order from CONTENT ANALYSIS
// rather than explicit indicators like "Tutorial 1, 2, 3" or "Beginner/Advanced" labels.
//
// TOPIC: JavaScript Asynchronous Programming (Various Creators)
// Why this series is ideal for IMPLICIT ordering tests:
// 1. Multiple creators = no channel-based ordering hints
// 2. NO explicit difficulty markers in titles (no "Beginner", "Part 1", etc.)
// 3. Clear prerequisite chain that must be inferred from content:
//    - Callbacks came first historically → Promises solve callback hell → Async/await wraps Promises
// 4. Short videos (1-8 min) minimize processing time
//
// EXPECTED ORDER must be inferred by understanding content:
// 1. "JavaScript in 100 Seconds" - Language overview, must come first
// 2. "What is a callback?" - Fundamental async concept, no prerequisites beyond basic JS
// 3. "JavaScript Promise in 100 Seconds" - Promises solve callback problems (requires understanding callbacks)
// 4. "JavaScript Async Await" - Syntactic sugar for Promises (requires understanding Promises)
// 5. "Closures Explained" - Advanced function concept (flexible positioning, tests nuanced ordering)
export const IMPLICIT_ORDER_VIDEOS = {
  // Videos with NO explicit ordering indicators - LLM must infer order from content
  javascriptAsync: {
    description: 'JavaScript async concepts - NO explicit difficulty labels, order must be inferred from content',
    expectedOrder: [
      {
        id: 'DHjqpvDnNGE',
        url: 'https://www.youtube.com/watch?v=DHjqpvDnNGE',
        title: 'JavaScript in 100 Seconds',
        inferredLevel: 'foundational', // Not in title - must be inferred
        duration: 156, // 2:36
        prerequisiteChain: 'None - this is the language overview',
      },
      {
        id: 'xHneyv38Jro',
        url: 'https://www.youtube.com/watch?v=xHneyv38Jro',
        title: 'What is a callback?',
        inferredLevel: 'beginner', // Not in title - must be inferred from content
        duration: 286, // 4:46
        prerequisiteChain: 'Requires basic JS knowledge',
      },
      {
        id: 'RvYYCGs45L4',
        url: 'https://www.youtube.com/watch?v=RvYYCGs45L4',
        title: 'JavaScript Promise in 100 Seconds',
        inferredLevel: 'intermediate', // Not in title - must be inferred
        duration: 99, // 1:39
        prerequisiteChain: 'Promises solve callback hell - requires understanding callbacks first',
      },
      {
        id: 'V_Kr9OSfDeU',
        url: 'https://www.youtube.com/watch?v=V_Kr9OSfDeU',
        title: 'JavaScript Async Await',
        inferredLevel: 'intermediate-advanced', // Not in title
        duration: 451, // 7:31
        prerequisiteChain: 'async/await is syntactic sugar for Promises - requires Promise understanding',
      },
      {
        id: 'vKJpN5FAeF4',
        url: 'https://www.youtube.com/watch?v=vKJpN5FAeF4',
        title: 'Closures Explained in 100 Seconds',
        inferredLevel: 'advanced', // Not in title
        duration: 297, // 4:57
        prerequisiteChain: 'Advanced function concept - requires deep function understanding',
      },
    ],
  },
};

// Combine all videos for seeding, deduplicating URLs
const ALL_TEST_VIDEOS = [
  ...new Set([
    ...TEST_VIDEOS,
    ...ORDERED_TEST_VIDEOS.pythonOOP.expectedOrder.map(v => v.url),
    ...ORDERED_TEST_VIDEOS.fitness.videos.map(v => v.url),
    ...IMPLICIT_ORDER_VIDEOS.javascriptAsync.expectedOrder.map(v => v.url),
  ]),
];

// Minimum number of indexed segments required before tests can run
// 15 videos (6 Python OOP + 4 fitness/kettlebell + 5 JS async) with typical processing yields ~50-70 segments
// This prevents E2E test timeout while still ensuring content is indexed
const MIN_SEGMENTS_REQUIRED = 40;
// Maximum wait time for video processing (5 minutes)
const MAX_WAIT_TIME_MS = 5 * 60 * 1000;
// Polling interval
const POLL_INTERVAL_MS = 10 * 1000;

interface VideoProgress {
  id: string;
  url: string;
  status: string;
  stage: string;
  queuePosition?: number;
  eta?: number;
  waitSeconds?: number;
  processingSeconds?: number;
}

async function getVideoProgress(videoId: string): Promise<VideoProgress | null> {
  try {
    const response = await fetch(`${API_URL}/api/v1/jobs/video/${videoId}/progress`);
    if (response.ok) {
      const data = await response.json();
      return {
        id: videoId,
        url: '',
        status: data.status,
        stage: data.current_stage || 'unknown',
        queuePosition: data.queue_position,
        eta: data.estimated_time_remaining,
        waitSeconds: data.total_wait_seconds,
        processingSeconds: data.total_processing_seconds,
      };
    }
  } catch {
    // Ignore errors
  }
  return null;
}

function formatTime(seconds: number | undefined): string {
  if (seconds === undefined || seconds === null) return '-';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

async function monitorBatchProgress(videoIds: Map<string, string>): Promise<boolean> {
  const startTime = Date.now();
  
  console.log(`\n[global-setup] Monitoring batch progress for ${videoIds.size} videos...`);
  console.log('[global-setup] ┌──────────────────────────────────────────────────────────────────┐');
  
  while (Date.now() - startTime < MAX_WAIT_TIME_MS) {
    const elapsed = Math.round((Date.now() - startTime) / 1000);
    const progressList: VideoProgress[] = [];
    
    // Fetch progress for all videos
    for (const [videoId] of videoIds) {
      const progress = await getVideoProgress(videoId);
      if (progress) {
        progressList.push(progress);
      }
    }
    
    // Count statuses
    const completed = progressList.filter(p => p.status === 'completed').length;
    const processing = progressList.filter(p => p.status === 'processing').length;
    const pending = progressList.filter(p => p.status === 'pending').length;
    const failed = progressList.filter(p => p.status === 'failed').length;
    
    // Find current processing video for details
    const currentVideo = progressList.find(p => p.status === 'processing');
    const queueInfo = currentVideo 
      ? `stage=${currentVideo.stage}, queue=${currentVideo.queuePosition ?? '-'}, eta=${formatTime(currentVideo.eta)}`
      : '';
    
    console.log(`[global-setup] │ [${elapsed}s] ✓${completed} ⚙${processing} ⏳${pending} ✗${failed} ${queueInfo}`);
    
    // Check completion via coverage endpoint
    try {
      const coverageResponse = await fetch(`${API_URL}/api/v1/copilot/coverage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      
      if (coverageResponse.ok) {
        const coverage = await coverageResponse.json();
        const segments = coverage.segmentCount || 0;
        
        if (segments >= MIN_SEGMENTS_REQUIRED) {
          console.log('[global-setup] └──────────────────────────────────────────────────────────────────┘');
          console.log(`[global-setup] ✓ Ready! ${segments} segments indexed, ${completed} videos completed`);
          
          // Log final processing stats
          console.log('\n[global-setup] Processing Summary:');
          for (const progress of progressList) {
            if (progress.status === 'completed') {
              console.log(`  ✓ ${progress.id.slice(0, 8)}... wait=${formatTime(progress.waitSeconds)} proc=${formatTime(progress.processingSeconds)}`);
            }
          }
          
          return true;
        }
      }
    } catch {
      // Ignore coverage check errors
    }
    
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  
  console.log('[global-setup] └──────────────────────────────────────────────────────────────────┘');
  console.log(`[global-setup] ⚠ Timeout waiting for video processing. Tests may fail.`);
  return false;
}

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
  
  // Track video IDs for progress monitoring
  const videoIds = new Map<string, string>(); // id -> url

  for (const url of ALL_TEST_VIDEOS) {
    try {
      const response = await fetch(`${API_URL}/api/v1/videos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`  ✓ Submitted: ${data.title || url}`);
        if (data.id) {
          videoIds.set(data.id, url);
        }
        submitted++;
      } else if (response.status === 409) {
        // Video already exists - try to get its ID for monitoring
        const existingResponse = await fetch(`${API_URL}/api/v1/videos?url=${encodeURIComponent(url)}`);
        if (existingResponse.ok) {
          const existingData = await existingResponse.json();
          if (existingData.items?.[0]?.id) {
            videoIds.set(existingData.items[0].id, url);
          }
        }
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

  // Store video IDs for tests to use
  // Tests that need to monitor progress can access these
  process.env.SEEDED_VIDEO_IDS = JSON.stringify(Array.from(videoIds.keys()));
  
  // If WATCH_QUEUE_PROGRESS is set, don't wait here - let the test do it
  // This allows Playwright to watch the UI update during processing
  if (process.env.WATCH_QUEUE_PROGRESS === 'true') {
    console.log('[global-setup] WATCH_QUEUE_PROGRESS=true - skipping wait, tests will monitor UI');
    return;
  }

  // Monitor batch progress with detailed queue/ETA tracking
  if (videoIds.size > 0) {
    await monitorBatchProgress(videoIds);
  } else {
    // Fallback to simple wait if we couldn't get video IDs
    await waitForVideoProcessing();
  }
}

export default globalSetup;
