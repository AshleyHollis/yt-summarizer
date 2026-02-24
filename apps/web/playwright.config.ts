import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for E2E tests
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  // Test directory
  testDir: './e2e',

  // Global setup - seeds test videos before tests run
  globalSetup: process.env.USE_EXTERNAL_SERVER ? './e2e/global-setup.ts' : undefined,

  // Maximum timeout for each test
  // 180s on CI (preview E2E against live backend with DeepSeek-V3.2 which can be slow),
  // test.slow() triples this to 540s for complex multi-LLM-call tests
  timeout: 180_000,

  // Run tests in files in parallel
  fullyParallel: true,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Retry failed tests - LLM responses can be flaky
  // CI: 1 retry for fast failure signal, Local: 1 retry for quick feedback
  retries: 1,

  // Run tests in parallel - LLM rate limiting is handled at the app level
  // with smart retry that uses Retry-After headers
  // 4 workers on CI to keep E2E under 30 min (172 tests × ~10s avg / 4 workers ≈ 7 min)
  workers: process.env.CI ? 4 : undefined,

  // Reporter to use
  reporter: [
    ['html', { open: 'never' }],
    ['list'],
  ],

  // Shared settings for all the projects below
  use: {
    // Base URL to use in actions like `await page.goto('/')`
    baseURL: process.env.BASE_URL || 'http://localhost:3000',

    // Collect trace when retrying the failed test
    trace: 'on-first-retry',

    // Take screenshot on failure - optimized for smaller file size
    screenshot: 'only-on-failure',

    // Use smaller viewport to reduce screenshot size for LLM context
    viewport: { width: 1280, height: 720 },
  },

  // Configure projects for major browsers
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Run local dev server before starting the tests
  // Note: When using Aspire, you should start the server externally
  // and set USE_EXTERNAL_SERVER=true to skip webServer
  webServer: process.env.USE_EXTERNAL_SERVER
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !process.env.CI,
        timeout: 120_000, // 2 minutes for Next.js to start
      },
});
