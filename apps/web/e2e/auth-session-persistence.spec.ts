/**
 * E2E Tests for Auth0 Session Persistence (User Story 1)
 *
 * Tests that authenticated sessions persist across page refreshes and navigation.
 *
 * Test Coverage:
 * 1. Session persists after page refresh
 * 2. Session persists across navigation
 * 3. User info remains consistent across page loads
 * 4. Session cookie has correct expiration and security settings
 *
 * Prerequisites:
 * - Auth0 tenant configured with rolling sessions
 * - Test user credentials set in environment variables
 * - Auth setup (auth.setup.ts) has run successfully
 *
 * IMPORTANT: These tests verify that the Auth0 SDK properly manages sessions
 * using encrypted cookies (appSession) with rolling expiration (24 hours default).
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Session Persistence @auth', () => {
  /**
   * Skip all tests if auth is not configured
   */
  test.skip(
    () => {
      const authFile = path.join(__dirname, '../playwright/.auth/user.json');
      return !fs.existsSync(authFile);
    },
    'Auth0 not configured - set AUTH0_* environment variables to run auth tests'
  );

  test.describe('Page Refresh', () => {
    test('user remains authenticated after page refresh', async ({ page }) => {
      // Navigate to the app
      await page.goto('/');

      // Verify user is authenticated (user profile visible)
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Get user info before refresh
      const userInfoBefore = await userProfile.textContent();

      // Refresh the page
      await page.reload();

      // User should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // User info should remain the same
      const userInfoAfter = await userProfile.textContent();
      expect(userInfoAfter).toBe(userInfoBefore);
    });

    test('session persists after hard refresh', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Hard refresh (bypass cache)
      await page.reload({ waitUntil: 'networkidle' });

      // Should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });

    test('session survives multiple consecutive refreshes', async ({ page }) => {
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Refresh multiple times
      for (let i = 0; i < 3; i++) {
        await page.reload();
        await expect(userProfile).toBeVisible({ timeout: 10000 });
      }
    });
  });

  test.describe('Navigation Persistence', () => {
    test('session persists when navigating between pages', async ({ page }) => {
      // Start at home
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate to add page
      await page.goto('/add');

      // Should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate back to home
      await page.goto('/');

      // Should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });

    test('session persists when using browser back button', async ({ page }) => {
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate to another page
      await page.goto('/add');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Use browser back button
      await page.goBack();

      // Should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });

    test('session persists when using browser forward button', async ({ page }) => {
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate to another page
      await page.goto('/add');

      // Go back
      await page.goBack();

      // Go forward
      await page.goForward();

      // Should still be authenticated
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('User Info Consistency', () => {
    test('user email remains consistent across pages', async ({ page }) => {
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Get user info on home page
      const userInfoHome = await userProfile.textContent();

      // Navigate to add page
      await page.goto('/add');

      // Get user info on add page
      const userInfoAdd = await userProfile.textContent();

      // Should be identical
      expect(userInfoAdd).toBe(userInfoHome);
    });

    test('user role remains consistent across navigation', async ({ page }) => {
      await page.goto('/');

      const roleBadge = page.getByTestId('role-badge');
      const roleBadgeExists = (await roleBadge.count()) > 0;

      if (roleBadgeExists) {
        const roleTextHome = await roleBadge.textContent();

        // Navigate to another page
        await page.goto('/add');

        // Role should remain the same
        const roleTextAdd = await roleBadge.textContent();
        expect(roleTextAdd).toBe(roleTextHome);
      } else {
        // If no role badge, it should remain absent on other pages
        await page.goto('/add');
        expect(await roleBadge.count()).toBe(0);
      }
    });

    test('user avatar remains consistent across pages', async ({ page }) => {
      await page.goto('/');

      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      const avatar = userProfile.locator('img, [data-testid="user-avatar"]').first();
      const avatarSrcHome = await avatar.getAttribute('src');

      // Navigate to add page
      await page.goto('/add');

      const avatarSrcAdd = await avatar.getAttribute('src');

      // Avatar source should be the same
      expect(avatarSrcAdd).toBe(avatarSrcHome);
    });
  });

  test.describe('Session Cookie Properties', () => {
    test('session cookie is HTTPOnly for security', async ({ page, context }) => {
      await page.goto('/');

      // Get cookies
      const cookies = await context.cookies();

      // Find the Auth0 session cookie (appSession)
      const sessionCookie = cookies.find((c) => c.name === 'appSession');

      if (sessionCookie) {
        // Should be HTTPOnly to prevent XSS attacks
        expect(sessionCookie.httpOnly).toBe(true);
      }
    });

    test('session cookie is Secure in production', async ({ page, context }) => {
      await page.goto('/');

      const cookies = await context.cookies();
      const sessionCookie = cookies.find((c) => c.name === 'appSession');

      if (sessionCookie && page.url().startsWith('https://')) {
        // Should be Secure when using HTTPS
        expect(sessionCookie.secure).toBe(true);
      }
    });

    test('session cookie has SameSite attribute', async ({ page, context }) => {
      await page.goto('/');

      const cookies = await context.cookies();
      const sessionCookie = cookies.find((c) => c.name === 'appSession');

      if (sessionCookie) {
        // Should have SameSite attribute for CSRF protection
        expect(sessionCookie.sameSite).toBeTruthy();
      }
    });
  });

  test.describe('Session State Across Tabs', () => {
    test('session is shared across multiple tabs', async ({ browser }) => {
      // Create first context with auth
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page1 = await context.newPage();
      await page1.goto('http://localhost:3000/');

      // Verify authenticated in first tab
      const userProfile1 = page1.getByTestId('user-profile');
      await expect(userProfile1).toBeVisible({ timeout: 10000 });

      // Open second tab in same context
      const page2 = await context.newPage();
      await page2.goto('http://localhost:3000/');

      // Should also be authenticated in second tab
      const userProfile2 = page2.getByTestId('user-profile');
      await expect(userProfile2).toBeVisible({ timeout: 10000 });

      await context.close();
    });

    test('logout in one tab affects other tabs', async ({ browser }) => {
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page1 = await context.newPage();
      await page1.goto('http://localhost:3000/');

      const page2 = await context.newPage();
      await page2.goto('http://localhost:3000/');

      // Both tabs should be authenticated
      await expect(page1.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });
      await expect(page2.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Logout in first tab
      const logoutButton = page1.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for logout to complete
      await page1.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Refresh second tab - should also be logged out
      await page2.reload();

      // Second tab should now show login page or redirect to login
      await page2.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      await context.close();
    });
  });

  test.describe('Session Expiration (Manual Test)', () => {
    /**
     * These tests document expected session expiration behavior.
     * They are skipped because they require waiting for session timeout (24 hours default).
     *
     * For manual testing:
     * 1. Configure Auth0 with a short session timeout (e.g., 5 minutes) in test environment
     * 2. Authenticate and wait for timeout
     * 3. Verify session expires and user is redirected to login
     */

    test.skip('session expires after inactivity timeout', async ({ page }) => {
      // This would require waiting for session expiration
      // Default Auth0 session timeout is 24 hours
      // For testing, configure a shorter timeout in Auth0 Dashboard

      await page.goto('/');
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Wait for session to expire (would need to configure short timeout)
      // await page.waitForTimeout(SESSION_TIMEOUT_MS);

      // Refresh page
      // await page.reload();

      // Should redirect to login
      // await expect(page).toHaveURL(/\/login/);
    });

    test.skip('session is refreshed on activity (rolling session)', async ({ page }) => {
      // Auth0 uses rolling sessions by default
      // Each request extends the session expiration

      await page.goto('/');

      // Navigate between pages (activity)
      await page.goto('/add');
      await page.goto('/');

      // Session should be extended, not expired
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });
  });
});
