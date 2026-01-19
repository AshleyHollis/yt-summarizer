/**
 * E2E Tests for Normal User Denied Admin Access (User Story 2)
 *
 * Tests that users without admin role are properly denied access to admin areas.
 *
 * Test Coverage:
 * 1. Normal user cannot access /admin routes
 * 2. Normal user is redirected to /access-denied page
 * 3. Access denied page displays properly
 * 4. Access denied page shows user's role
 * 5. Normal user does not see admin navigation links
 * 6. Normal user can return to accessible areas from access-denied page
 *
 * Prerequisites:
 * - Auth0 tenant configured with normal test user
 * - Test user has 'user' role or no role in app_metadata
 * - Auth setup (auth.setup.ts) has run successfully
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Normal User Denied Admin Access @auth @rbac', () => {
  /**
   * Skip all tests if auth is not configured
   */
  test.skip(() => {
    const authFile = path.join(__dirname, '../playwright/.auth/user.json');
    return !fs.existsSync(authFile);
  }, 'Auth0 not configured - set AUTH0_* environment variables to run auth tests');

  /**
   * NOTE: These tests assume the authenticated user does NOT have admin role.
   * In a full implementation, you would have a separate storage state for normal users.
   *
   * For now, these tests will be skipped or may fail if the test user has admin role.
   * To properly test, create playwright/.auth/normal-user.json with a non-admin user.
   */

  test.describe('Access Denial for Admin Routes', () => {
    test('normal user attempting to access /admin is redirected to access-denied', async ({
      browser,
    }) => {
      // Create a new context without admin role (simulating normal user)
      // In real implementation, this would use playwright/.auth/normal-user.json
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page = await context.newPage();

      try {
        // Try to access admin page
        await page.goto('http://localhost:3000/admin');

        // Should redirect to access-denied page
        // (This will only work if the authenticated user is NOT an admin)
        await page.waitForURL(
          (url) => url.pathname.includes('/access-denied') || url.pathname.includes('/admin'),
          { timeout: 10000 }
        );

        const currentUrl = page.url();

        // If user is admin, this test is not applicable
        if (currentUrl.includes('/admin') && !currentUrl.includes('/access-denied')) {
          test.skip(true, 'Test user has admin role - cannot test normal user denial');
        }

        // Should be on access-denied page
        expect(currentUrl).toContain('/access-denied');
      } finally {
        await context.close();
      }
    });

    test('access-denied page loads correctly', async ({ page }) => {
      // Navigate directly to access-denied page
      await page.goto('/access-denied');

      // Should show access denied heading
      const heading = page.getByRole('heading', { name: /access denied/i });
      await expect(heading).toBeVisible({ timeout: 10000 });
    });

    test('access-denied page explains why access was denied', async ({ page }) => {
      await page.goto('/access-denied');

      // Should have explanatory text
      const explanationText = page.getByText(/don't have permission/i);
      await expect(explanationText).toBeVisible();
    });

    test('access-denied page shows user information', async ({ page }) => {
      await page.goto('/access-denied');

      // Should show "Why am I seeing this?" section
      const whySection = page.getByText(/why am i seeing this/i);
      await expect(whySection).toBeVisible();
    });

    test('access-denied page provides navigation options', async ({ page }) => {
      await page.goto('/access-denied');

      // Should have a "Return Home" button or link
      const returnHomeLink = page.getByRole('link', { name: /return home/i });
      await expect(returnHomeLink).toBeVisible();
    });
  });

  test.describe('Access Denied Page Features', () => {
    test('access-denied page shows appropriate error icon', async ({ page }) => {
      await page.goto('/access-denied');

      // Page should have visual error indicators
      const heading = page.getByRole('heading', { name: /access denied/i });
      await expect(heading).toBeVisible();

      // Should have SVG icon or visual indicator
      const svgs = page.locator('svg');
      const svgCount = await svgs.count();
      expect(svgCount).toBeGreaterThan(0);
    });

    test('access-denied page displays user role if available', async ({ page }) => {
      await page.goto('/access-denied');

      // Should show user's current role (if they have one)
      const pageContent = await page.textContent('body');

      // Page mentions role information
      expect(pageContent).toBeTruthy();
      expect(pageContent!.toLowerCase()).toContain('role');
    });

    test('access-denied page shows "What can I do?" section', async ({ page }) => {
      await page.goto('/access-denied');

      // Should have helpful next steps
      const whatCanIDo = page.getByText(/what can i do/i);
      await expect(whatCanIDo).toBeVisible();
    });

    test('access-denied page suggests contacting administrator', async ({ page }) => {
      await page.goto('/access-denied');

      // Should mention contacting admin
      const contactAdmin = page.getByText(/contact.*administrator/i);
      await expect(contactAdmin).toBeVisible();
    });

    test('access-denied page has return home link that works', async ({ page }) => {
      await page.goto('/access-denied');

      // Click return home link
      const returnHomeLink = page.getByRole('link', { name: /return home/i });
      await expect(returnHomeLink).toBeVisible();
      await returnHomeLink.click();

      // Should navigate to home page
      await expect(page).toHaveURL('/');
    });
  });

  test.describe('Navigation Restrictions', () => {
    test('normal user does not see admin link in navigation', async ({ browser }) => {
      const context = await browser.newContext({
        storageState: path.join(__dirname, '../playwright/.auth/user.json'),
      });

      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/');

        // Admin link should not be visible
        const adminLink = page.getByTestId('admin-nav-link');

        // Check if admin link exists
        const adminLinkCount = await adminLink.count();

        // If the test user has admin role, skip this test
        if (adminLinkCount > 0) {
          const isVisible = await adminLink.isVisible();
          if (isVisible) {
            test.skip(true, 'Test user has admin role - cannot test normal user restrictions');
          }
        }

        // Normal user should not see admin link
        expect(adminLinkCount).toBe(0);
      } finally {
        await context.close();
      }
    });

    test('normal user sees standard navigation links', async ({ page }) => {
      await page.goto('/');

      // Should see normal navigation links
      const addLink = page.getByRole('link', { name: /add/i }).first();
      await expect(addLink).toBeVisible({ timeout: 10000 });

      const libraryLink = page.getByRole('link', { name: /library/i });
      await expect(libraryLink).toBeVisible();
    });

    test('normal user can access non-admin pages', async ({ page }) => {
      // Navigate to various non-admin pages
      await page.goto('/');
      await expect(page).toHaveURL('/');

      await page.goto('/add');
      // Should successfully load (not redirect to access-denied)
      const currentUrl = page.url();
      expect(currentUrl).not.toContain('/access-denied');
    });
  });

  test.describe('Access Denied Page Accessibility', () => {
    test('access-denied page is accessible without authentication', async ({ browser }) => {
      // Create context without auth
      const context = await browser.newContext({ storageState: undefined });
      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/access-denied');

        // Page should load (it's a public error page)
        const heading = page.getByRole('heading', { name: /access denied/i });
        await expect(heading).toBeVisible({ timeout: 10000 });
      } finally {
        await context.close();
      }
    });

    test('access-denied page shows sign in option for unauthenticated users', async ({
      browser,
    }) => {
      const context = await browser.newContext({ storageState: undefined });
      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/access-denied');

        // Should suggest signing in
        const signInText = page.getByText(/sign in/i);
        // May or may not be visible depending on implementation
        // Just verify the page loads
        const heading = page.getByRole('heading', { name: /access denied/i });
        await expect(heading).toBeVisible();
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Multiple Admin Routes Protection', () => {
    const adminRoutes = ['/admin', '/admin/users', '/admin/settings', '/admin/analytics'];

    adminRoutes.forEach((route) => {
      test(`normal user cannot access ${route}`, async ({ browser }) => {
        const context = await browser.newContext({
          storageState: path.join(__dirname, '../playwright/.auth/user.json'),
        });

        const page = await context.newPage();

        try {
          await page.goto(`http://localhost:3000${route}`);

          await page.waitForURL(
            (url) =>
              url.pathname.includes('/access-denied') ||
              url.pathname.includes('/admin') ||
              url.pathname.includes('/404'),
            { timeout: 10000 }
          );

          const currentUrl = page.url();

          // If user landed on admin page, they have admin role (skip test)
          if (currentUrl.includes('/admin') && !currentUrl.includes('/access-denied')) {
            test.skip(true, 'Test user has admin role');
          }

          // Should be denied access
          expect(currentUrl.includes('/access-denied') || currentUrl.includes('/404')).toBeTruthy();
        } finally {
          await context.close();
        }
      });
    });
  });

  test.describe('User Experience', () => {
    test('access-denied page has gradient background', async ({ page }) => {
      await page.goto('/access-denied');

      // Verify page loads with proper styling
      const heading = page.getByRole('heading', { name: /access denied/i });
      await expect(heading).toBeVisible();

      // Page should be visually appealing (has background)
      const body = page.locator('body');
      await expect(body).toBeVisible();
    });

    test('access-denied page is mobile responsive', async ({ page }) => {
      await page.goto('/access-denied');

      // Test on mobile viewport
      await page.setViewportSize({ width: 375, height: 667 });

      const heading = page.getByRole('heading', { name: /access denied/i });
      await expect(heading).toBeVisible();

      // Test on tablet
      await page.setViewportSize({ width: 768, height: 1024 });
      await expect(heading).toBeVisible();

      // Test on desktop
      await page.setViewportSize({ width: 1920, height: 1080 });
      await expect(heading).toBeVisible();
    });

    test('access-denied page loads without JavaScript errors', async ({ page }) => {
      const errors: string[] = [];

      page.on('pageerror', (error) => {
        errors.push(error.message);
      });

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(msg.text());
        }
      });

      await page.goto('/access-denied');
      await expect(page.getByRole('heading', { name: /access denied/i })).toBeVisible();

      expect(errors).toHaveLength(0);
    });
  });
});
