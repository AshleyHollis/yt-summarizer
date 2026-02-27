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

  // Run tests in parallel - 4 workers on CI keeps total run time under
  // the 60-minute GitHub Actions limit. The submitQuery() fix (waiting for
  // networkidle before typing + input.toHaveValue("") confirmation) prevents
  // the race condition that caused earlier failures, so concurrency is safe.
  workers: process.env.CI ? 4 : undefined,

  // Reporter to use
  reporter: [['html', { open: 'never' }], ['list']],

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
    // Setup project runs first - authenticates with Auth0 and saves storage state
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },
    // Chromium tests - use authenticated storage state when available
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Use authenticated storage state for tests that require auth
        // Tests can override this by setting storageState: undefined in test.use()
        storageState: 'playwright/.auth/user.json',
      },
      // Run setup before chromium tests (only if setup test exists)
      dependencies: ['setup'],
    },
    // Admin-specific tests - use admin auth state
    {
      name: 'chromium-admin',
      use: {
        ...devices['Desktop Chrome'],
        // Use admin authenticated storage state for admin-only tests
        storageState: 'playwright/.auth/admin.json',
      },
      // Run setup before admin tests
      dependencies: ['setup'],
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
