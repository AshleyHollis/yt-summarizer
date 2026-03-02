/**
 * Auth setup for Playwright E2E tests.
 *
 * This runs BEFORE auth-dependent tests and performs programmatic authentication
 * via the application's login flow.
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
 * - AUTH0_ISSUER_BASE_URL: Auth0 tenant domain (e.g., https://your-tenant.us.auth0.com)
 * - AUTH0_CLIENT_ID: Application client ID
 * - AUTH0_CLIENT_SECRET: Application client secret (optional for this flow)
 * - AUTH0_ADMIN_TEST_EMAIL: Admin test user email
 * - AUTH0_ADMIN_TEST_PASSWORD: Admin test user password
 * - AUTH0_USER_TEST_EMAIL: Normal test user email
 * - AUTH0_USER_TEST_PASSWORD: Normal test user password
 *
 * Implementation: T050 (Configure Playwright programmatic authentication)
 */

import { test as setup } from '@playwright/test';
import * as path from 'path';

const adminAuthFile = path.join(__dirname, '../playwright/.auth/admin.json');
const userAuthFile = path.join(__dirname, '../playwright/.auth/user.json');

/**
 * Authenticate via Auth0 Universal Login.
 *
 * Navigates directly to the API's /api/auth/login endpoint (which redirects to Auth0),
 * then fills the password on Auth0's own login page.
 *
 * IMPORTANT: We navigate to the API URL directly, NOT through the SWA. Azure SWA
 * intercepts /api/* as Azure Functions routes (returns 500 since we have no Functions).
 * The API sets the session cookie on its own domain, which is correct since the frontend
 * makes API calls directly to the API URL (via getClientApiUrl()).
 */
async function authenticateViaAuth0(
  page: import('@playwright/test').Page,
  email: string,
  password: string,
  label: string
): Promise<void> {
  // Use the API URL directly — SWA returns 500 for /api/* (Azure Functions interception)
  const apiUrl = process.env.API_URL || 'http://localhost:8000';
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  const loginUrl = `${apiUrl}/api/auth/login?connection=Username-Password-Authentication&login_hint=${encodeURIComponent(email)}&returnTo=${encodeURIComponent(baseUrl)}`;
  console.log(`[auth-setup] Navigating to Auth0 login for ${label} via ${apiUrl}...`);
  const response = await page.goto(loginUrl);
  console.log(`[auth-setup] After goto — URL: ${page.url()}, status: ${response?.status()}`);

  // Check for Auth0 error redirect (e.g., connection not enabled)
  const currentUrl = page.url();
  if (currentUrl.includes('error=') && currentUrl.includes('error_description=')) {
    const errorDesc = decodeURIComponent(new URL(currentUrl).searchParams.get('error_description') || 'unknown');
    throw new Error(`Auth0 returned error before login page: ${errorDesc}`);
  }

  // Wait for redirect to Auth0's login page
  await page.waitForURL((url) => url.hostname.includes('auth0.com'), { timeout: 20000 });
  console.log(`[auth-setup] Reached Auth0 login page for ${label}`);

  // Auth0 Universal Login — email may already be pre-filled via login_hint
  // Fill email if the field is visible and empty
  const emailInput = page.locator('input[name="username"], input[id="username"], input[type="email"]').first();
  try {
    await emailInput.waitFor({ timeout: 5000 });
    const currentEmail = await emailInput.inputValue();
    if (!currentEmail) {
      await emailInput.fill(email);
    }
  } catch {
    // email field not present or already filled — continue
  }

  // Fill password on Auth0's page
  const passwordInput = page
    .locator('input[name="password"], input[id="password"], input[type="password"]')
    .first();
  await passwordInput.waitFor({ timeout: 15000 });
  await passwordInput.fill(password);

  // Submit Auth0 login form
  const submitBtn = page.locator('button[name="action"], button[type="submit"]').first();
  await submitBtn.click();

  // Wait for redirect back to our app (away from auth0.com)
  await page.waitForURL((url) => !url.hostname.includes('auth0.com'), { timeout: 30000 });
  console.log(`[auth-setup] ✓ ${label} authenticated successfully — redirected to app`);
}

setup('authenticate as admin', async ({ page }) => {
  const email = process.env.AUTH0_ADMIN_TEST_EMAIL;
  const password = process.env.AUTH0_ADMIN_TEST_PASSWORD;

  if (!email || !password) {
    console.warn('[auth-setup] ⚠ Admin test credentials not set. Skipping admin authentication.');
    console.warn('[auth-setup] Set AUTH0_ADMIN_TEST_EMAIL and AUTH0_ADMIN_TEST_PASSWORD to enable admin tests.');
    return;
  }

  try {
    await authenticateViaAuth0(page, email, password, 'admin');
    await page.context().storageState({ path: adminAuthFile });
    console.log(`[auth-setup] ✓ Saved admin auth state to ${adminAuthFile}`);
  } catch (error) {
    console.error('[auth-setup] ✗ Admin authentication failed:', error);
    console.error(`[auth-setup] Current URL at failure: ${page.url()}`);
    await page.screenshot({ path: 'playwright/.auth/admin-failure.png' }).catch(() => {});
    console.error('[auth-setup] Tests requiring admin authentication will be skipped.');
  }
});

setup('authenticate as normal user', async ({ page }) => {
  const email = process.env.AUTH0_USER_TEST_EMAIL;
  const password = process.env.AUTH0_USER_TEST_PASSWORD;

  if (!email || !password) {
    console.warn('[auth-setup] ⚠ User test credentials not set. Skipping user authentication.');
    console.warn('[auth-setup] Set AUTH0_USER_TEST_EMAIL and AUTH0_USER_TEST_PASSWORD to enable user tests.');
    return;
  }

  try {
    await authenticateViaAuth0(page, email, password, 'normal user');
    await page.context().storageState({ path: userAuthFile });
    console.log(`[auth-setup] ✓ Saved user auth state to ${userAuthFile}`);
  } catch (error) {
    console.error('[auth-setup] ✗ User authentication failed:', error);
    console.error(`[auth-setup] Current URL at failure: ${page.url()}`);
    await page.screenshot({ path: 'playwright/.auth/user-failure.png' }).catch(() => {});
    console.error('[auth-setup] Tests requiring user authentication will be skipped.');
  }
});
