/**
 * Auth setup for Playwright E2E tests.
 *
 * This runs BEFORE auth-dependent tests and authenticates directly via
 * Auth0's Universal Login page, bypassing the app's /login route.
 *
 * IMPORTANT: This creates authenticated sessions for both admin and normal users.
 * Auth state is saved to playwright/.auth/ and reused across tests for performance.
 *
 * Prerequisites:
 * - Auth0 database connection created with username/password enabled
 * - Test user credentials from environment variables or Azure Key Vault:
 *   - AUTH0_ADMIN_TEST_EMAIL / AUTH0_ADMIN_TEST_PASSWORD (admin user)
 *   - AUTH0_USER_TEST_EMAIL / AUTH0_USER_TEST_PASSWORD (normal user)
 *
 * Environment Variables Required:
 * - AUTH0_ADMIN_TEST_EMAIL: Admin test user email
 * - AUTH0_ADMIN_TEST_PASSWORD: Admin test user password
 * - AUTH0_USER_TEST_EMAIL: Normal test user email
 * - AUTH0_USER_TEST_PASSWORD: Normal test user password
 *
 * Implementation: T050 (Configure Playwright programmatic authentication)
 */

import { test as setup, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const adminAuthFile = path.join(__dirname, '../playwright/.auth/admin.json');
const userAuthFile = path.join(__dirname, '../playwright/.auth/user.json');

/** Ensure the .auth directory exists so storage state can be saved. */
function ensureAuthDir() {
  const authDir = path.join(__dirname, '../playwright/.auth');
  if (!fs.existsSync(authDir)) {
    fs.mkdirSync(authDir, { recursive: true });
  }
}

/**
 * Save an empty (unauthenticated) storage state so Playwright can still load
 * the project even when authentication was skipped or failed.
 */
async function saveEmptyState(filePath: string) {
  ensureAuthDir();
  fs.writeFileSync(filePath, JSON.stringify({ cookies: [], origins: [] }));
}

/**
 * Authenticate via Auth0 Universal Login and save storage state.
 *
 * Navigates to /api/auth/login (which redirects to Auth0), fills credentials
 * on the Auth0 Universal Login page, then waits for the OAuth callback to
 * complete and return control to the app.
 */
async function authenticateViaAuth0(
  page: import('@playwright/test').Page,
  email: string,
  password: string,
  label: string
): Promise<boolean> {
  const loginUrl = `/api/auth/login?connection=Username-Password-Authentication&login_hint=${encodeURIComponent(email)}`;

  console.log(`[auth-setup] Navigating to Auth0 login for ${label}...`);
  await page.goto(loginUrl);

  // Wait for redirect to Auth0 Universal Login
  await page.waitForURL(/auth0\.com/, { timeout: 20000 });
  console.log(`[auth-setup] On Auth0 Universal Login page: ${page.url()}`);

  // Auth0 Universal Login – fill email if not pre-populated via login_hint
  const emailInput = page.locator('input[name="username"], input[id="username"], input[type="email"]').first();
  if (await emailInput.isVisible({ timeout: 3000 }).catch(() => false)) {
    const current = await emailInput.inputValue().catch(() => '');
    if (!current) {
      await emailInput.fill(email);
    }
  }

  // Fill password
  const passwordInput = page.locator('input[name="password"], input[id="password"], input[type="password"]').first();
  await passwordInput.waitFor({ timeout: 15000 });
  await passwordInput.fill(password);

  // Submit (Auth0 Universal Login uses a button[name="action"] or button[type="submit"])
  const submitBtn = page.locator('button[name="action"], button[type="submit"]').first();
  await submitBtn.click();

  // Wait for OAuth callback to complete and redirect back to the app
  const baseURL = page.context().browser()?.contexts()[0]?.pages()[0]?.url() ?? '';
  await page.waitForURL(
    (url) => !url.hostname.includes('auth0.com'),
    { timeout: 30000 }
  );
  console.log(`[auth-setup] Redirected back to app: ${page.url()}`);

  // Give the app a moment to process the session
  await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});

  return true;
}

/**
 * Authenticate as admin user and save storage state.
 */
setup('authenticate as admin', async ({ page }) => {
  const email = process.env.AUTH0_ADMIN_TEST_EMAIL;
  const password = process.env.AUTH0_ADMIN_TEST_PASSWORD;

  ensureAuthDir();

  if (!email || !password) {
    console.warn('[auth-setup] ⚠ Admin test credentials not set. Skipping admin authentication.');
    console.warn(
      '[auth-setup] Set AUTH0_ADMIN_TEST_EMAIL and AUTH0_ADMIN_TEST_PASSWORD to enable admin tests.'
    );
    await saveEmptyState(adminAuthFile);
    return;
  }

  console.log('[auth-setup] Authenticating as admin user...');

  try {
    await authenticateViaAuth0(page, email, password, 'admin');

    await page.context().storageState({ path: adminAuthFile });
    console.log(`[auth-setup] ✓ Saved admin auth state to ${adminAuthFile}`);
  } catch (error) {
    console.error('[auth-setup] ✗ Admin authentication failed:', error);
    console.error('[auth-setup] Tests requiring admin authentication will run unauthenticated.');
    await saveEmptyState(adminAuthFile);
  }
});

/**
 * Authenticate as normal user and save storage state.
 */
setup('authenticate as normal user', async ({ page }) => {
  const email = process.env.AUTH0_USER_TEST_EMAIL;
  const password = process.env.AUTH0_USER_TEST_PASSWORD;

  ensureAuthDir();

  if (!email || !password) {
    console.warn('[auth-setup] ⚠ User test credentials not set. Skipping user authentication.');
    console.warn(
      '[auth-setup] Set AUTH0_USER_TEST_EMAIL and AUTH0_USER_TEST_PASSWORD to enable user tests.'
    );
    await saveEmptyState(userAuthFile);
    return;
  }

  console.log('[auth-setup] Authenticating as normal user...');

  try {
    await authenticateViaAuth0(page, email, password, 'user');

    await page.context().storageState({ path: userAuthFile });
    console.log(`[auth-setup] ✓ Saved user auth state to ${userAuthFile}`);
  } catch (error) {
    console.error('[auth-setup] ✗ User authentication failed:', error);
    console.error('[auth-setup] Tests requiring user authentication will run unauthenticated.');
    await saveEmptyState(userAuthFile);
  }
});

/**
 * NOTE: This implementation authenticates directly via Auth0 Universal Login.
 *
 * Benefits:
 * - Does not depend on the app's /login page (which can return 404 on SWA)
 * - Tests the actual OAuth flow users go through
 * - No special Auth0 grant types required (uses standard Authorization Code flow)
 * - Auth state is reused across tests for performance
 * - Gracefully saves empty state if auth fails, preventing "file not found" errors
 *
 * Performance:
 * - First run: ~5-10 seconds per user (Auth0 round trip)
 * - Subsequent tests: <100ms (reuse saved storage state)
 * - Total setup time: ~10-20 seconds for both users
 *
 * Alternative approaches considered:
 * - Resource Owner Password Grant: Requires Auth0 Enterprise tier
 * - Direct token injection: Complex with @auth0/nextjs-auth0 encrypted sessions
 * - App /login page: Fragile on SWA (route can 404 due to platform routing)
 */
