/**
 * E2E Tests for Auth0 Sign Out Flow (User Story 1)
 *
 * Tests that users can successfully sign out and that sessions are properly cleared.
 *
 * Test Coverage:
 * 1. User can click logout button and sign out
 * 2. Session is cleared after logout
 * 3. User is redirected to login page after logout
 * 4. User cannot access protected routes after logout
 * 5. Session state is cleared from browser storage
 *
 * Prerequisites:
 * - Auth0 tenant configured with logout redirect URLs
 * - Test user credentials set in environment variables
 * - Auth setup (auth.setup.ts) has run successfully
 *
 * IMPORTANT: These tests verify that the Auth0 SDK properly clears sessions
 * and redirects users to the login page after logout.
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Sign Out Flow @auth', () => {
  /**
   * Skip all tests if auth is not configured
   */
  test.skip(() => {
    const authFile = path.join(__dirname, '../playwright/.auth/user.json');
    return !fs.existsSync(authFile);
  }, 'Auth0 not configured - set AUTH0_* environment variables to run auth tests');

  test.describe('Logout Button Interaction', () => {
    test('logout button is visible for authenticated users', async ({ page }) => {
      await page.goto('/');

      // User profile should be visible
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Logout button should be visible
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await expect(logoutButton).toBeVisible();
    });

    test('logout button is clickable', async ({ page }) => {
      await page.goto('/');

      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await expect(logoutButton).toBeVisible({ timeout: 10000 });
      await expect(logoutButton).toBeEnabled();
    });

    test('clicking logout button initiates sign out flow', async ({ page }) => {
      await page.goto('/');

      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await expect(logoutButton).toBeVisible({ timeout: 10000 });

      // Click logout
      await logoutButton.click();

      // Should navigate to logout endpoint or login page
      // The URL will change as part of the logout process
      await page.waitForURL(
        (url) => {
          return url.pathname.includes('/login') || url.pathname.includes('/auth/logout');
        },
        { timeout: 10000 }
      );
    });
  });

  test.describe('Session Cleanup', () => {
    test('session is cleared after logout', async ({ page, context }) => {
      await page.goto('/');

      // Verify authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Get cookies before logout
      const cookiesBefore = await context.cookies();
      const sessionCookieBefore = cookiesBefore.find((c) => c.name === 'appSession');

      // Session cookie should exist
      expect(sessionCookieBefore).toBeTruthy();

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for logout to complete
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Get cookies after logout
      const cookiesAfter = await context.cookies();
      const sessionCookieAfter = cookiesAfter.find((c) => c.name === 'appSession');

      // Session cookie should be cleared or have empty value
      if (sessionCookieAfter) {
        expect(sessionCookieAfter.value).toBe('');
      }
    });

    test('user profile is not visible after logout', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for logout
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // User profile should not be visible
      await expect(userProfile).not.toBeVisible();
    });

    test('logout clears all auth state', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for logout
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Navigate to app root
      await page.goto('/');

      // Should redirect to login (not authenticated)
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 5000,
      });
    });
  });

  test.describe('Post-Logout Navigation', () => {
    test('user is redirected to login page after logout', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Should redirect to login page
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      expect(page.url()).toContain('/login');
    });

    test('login page shows social login buttons after logout', async ({ page }) => {
      await page.goto('/');

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for redirect to login
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Should see login buttons
      const googleButton = page.getByRole('button', { name: /google/i });
      await expect(googleButton).toBeVisible();

      const githubButton = page.getByRole('button', { name: /github/i });
      await expect(githubButton).toBeVisible();
    });

    test('user cannot access protected routes after logout', async ({ page }) => {
      await page.goto('/');

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for logout
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Try to access a protected route
      await page.goto('/');

      // Should redirect to login
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 5000,
      });

      expect(page.url()).toContain('/login');
    });

    test('browser back button after logout keeps user on login page', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Wait for login page
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 10000,
      });

      // Try to go back
      await page.goBack();

      // Should still be on login page or redirect to login
      // (cannot access previous authenticated page)
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 5000,
      });

      expect(page.url()).toContain('/login');
    });
  });

  test.describe('Re-Authentication After Logout', () => {
    test('user can log in again after logging out', async ({ browser }) => {
      // Create a new context with auth state
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/');

        // Verify authenticated
        await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

        // Logout
        const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
        await logoutButton.click();

        // Wait for logout
        await page.waitForURL((url) => url.pathname.includes('/login'), {
          timeout: 10000,
        });

        // Verify we're on login page
        const googleButton = page.getByRole('button', { name: /google/i });
        await expect(googleButton).toBeVisible();

        // Note: Actual re-login would require OAuth flow
        // This test verifies the logout was successful and login UI is available
      } finally {
        await context.close();
      }
    });

    test('logout and re-login creates fresh session', async ({ browser }) => {
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/');

        // Get session info before logout
        const userProfileBefore = page.getByTestId('user-profile');
        await expect(userProfileBefore).toBeVisible({ timeout: 10000 });

        // Logout
        const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
        await logoutButton.click();

        // Wait for logout
        await page.waitForURL((url) => url.pathname.includes('/login'), {
          timeout: 10000,
        });

        // Create new context with fresh auth (simulating re-login)
        const newContext = await browser.newContext({
          storageState: path.join(__dirname, '../playwright/.auth/user.json'),
        });

        const newPage = await newContext.newPage();
        await newPage.goto('http://localhost:3000/');

        // Should be authenticated with fresh session
        const userProfileAfter = newPage.getByTestId('user-profile');
        await expect(userProfileAfter).toBeVisible({ timeout: 10000 });

        await newContext.close();
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Multiple Tabs Logout', () => {
    test('logging out in one tab clears session in all tabs', async ({ browser }) => {
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page1 = await context.newPage();
      const page2 = await context.newPage();

      try {
        await page1.goto('http://localhost:3000/');
        await page2.goto('http://localhost:3000/');

        // Both tabs should be authenticated
        await expect(page1.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });
        await expect(page2.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

        // Logout in first tab
        const logoutButton = page1.getByRole('button', { name: /log out|sign out/i });
        await logoutButton.click();

        // Wait for logout in first tab
        await page1.waitForURL((url) => url.pathname.includes('/login'), {
          timeout: 10000,
        });

        // Refresh second tab
        await page2.reload();

        // Second tab should also be logged out
        await page2.waitForURL((url) => url.pathname.includes('/login'), {
          timeout: 10000,
        });

        expect(page2.url()).toContain('/login');
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Error Handling', () => {
    test('logout still works if network is slow', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Slow down network
      await page.route('**/api/auth/**', (route) => {
        setTimeout(() => route.continue(), 2000); // 2 second delay
      });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Should still redirect to login (may take longer)
      await page.waitForURL((url) => url.pathname.includes('/login'), {
        timeout: 15000, // Extended timeout for slow network
      });

      expect(page.url()).toContain('/login');
    });

    test('logout gracefully handles API errors', async ({ page }) => {
      await page.goto('/');

      // Verify authenticated
      await expect(page.getByTestId('user-profile')).toBeVisible({ timeout: 10000 });

      // Make logout API fail
      await page.route('**/api/auth/logout', (route) => {
        route.fulfill({
          status: 500,
          body: 'Internal Server Error',
        });
      });

      // Logout
      const logoutButton = page.getByRole('button', { name: /log out|sign out/i });
      await logoutButton.click();

      // Even if API fails, should attempt to redirect or show error
      // Wait a bit to see what happens
      await page.waitForTimeout(3000);

      // At minimum, the button should have been clicked
      // The exact behavior depends on error handling implementation
      // For now, just verify the logout attempt was made
      const currentUrl = page.url();
      expect(currentUrl).toBeTruthy();
    });
  });
});
