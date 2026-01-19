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
  // Increased to handle LLM rate limit retries (up to 5 retries with exponential backoff)
  timeout: 120_000,

  // Run tests in files in parallel
  fullyParallel: true,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Retry failed tests - LLM responses can be flaky
  // CI: 2 retries for stability, Local: 1 retry for quick feedback
  retries: process.env.CI ? 2 : 1,

  // Run tests in parallel - LLM rate limiting is handled at the app level
  // with smart retry that uses Retry-After headers
  workers: process.env.CI ? 1 : undefined,

  // Reporter to use
  reporter: [['html', { open: 'never' }], ['list']],

  // Shared settings for all the projects below
  use: {
    // Base URL to use in actions like `await page.goto('/')`
    baseURL: 'http://localhost:3000',

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
