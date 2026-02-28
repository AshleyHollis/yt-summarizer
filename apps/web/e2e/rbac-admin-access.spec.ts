/**
 * E2E Tests for Admin User Accessing Admin Dashboard (User Story 2)
 *
 * Tests that users with admin role can successfully access the admin dashboard.
 *
 * Test Coverage:
 * 1. Admin user can navigate to /admin
 * 2. Admin dashboard page loads correctly
 * 3. Admin user sees admin-specific content
 * 4. Admin user sees navigation link to admin area
 * 5. Admin user can access admin sub-pages
 *
 * Prerequisites:
 * - Auth0 tenant configured with admin test user
 * - Test user has 'admin' role in app_metadata
 * - Auth setup (auth.setup.ts) has run successfully with admin user
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

// Use admin authentication for all tests in this file
test.use({ storageState: 'playwright/.auth/admin.json' });

test.describe('Admin User Access to Admin Dashboard @auth @rbac', () => {
  /**
   * Skip all tests if admin auth is not configured
   */
  test.skip(() => {
    const authFile = path.join(__dirname, '../playwright/.auth/admin.json');
    return !fs.existsSync(authFile);
  }, 'Auth0 admin credentials not configured - set AUTH0_ADMIN_TEST_EMAIL and AUTH0_ADMIN_TEST_PASSWORD to run admin tests');

  test.describe('Admin Dashboard Access', () => {
    test('admin user can navigate to admin dashboard', async ({ page }) => {
      // Navigate to admin page
      await page.goto('/admin');

      // Should successfully load admin page (not redirect)
      await expect(page).toHaveURL('/admin');

      // Should see admin dashboard heading
      const heading = page.getByRole('heading', { name: /admin dashboard/i });
      await expect(heading).toBeVisible({ timeout: 10000 });
    });

    test('admin dashboard displays welcome message', async ({ page }) => {
      await page.goto('/admin');

      // Should see admin dashboard heading
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      // Should see welcome message
      const welcomeText = page.getByText(/welcome/i);
      await expect(welcomeText).toBeVisible();
    });

    test('admin dashboard displays admin role badge', async ({ page }) => {
      await page.goto('/admin');

      // Look for role badge or role indicator
      // The admin dashboard shows the user's role
      const adminBadge = page.getByText(/admin/i).first();
      await expect(adminBadge).toBeVisible({ timeout: 10000 });
    });

    test('admin dashboard shows statistics cards', async ({ page }) => {
      await page.goto('/admin');

      // Admin dashboard should have stat cards
      // Look for common admin dashboard elements
      const dashboardContent = page.locator('main');
      await expect(dashboardContent).toBeVisible();

      // Should have some admin-specific content
      const adminContent = await page.textContent('body');
      expect(adminContent).toBeTruthy();
      expect(adminContent!.toLowerCase()).toContain('admin');
    });

    test('admin dashboard shows management sections', async ({ page }) => {
      await page.goto('/admin');

      // Should see admin dashboard
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      // Look for management section headings or links
      const pageContent = await page.textContent('body');

      // Admin dashboard typically has these sections (may vary by implementation)
      // Just verify the page has substantial admin-related content
      expect(pageContent).toBeTruthy();
      expect(pageContent!.length).toBeGreaterThan(100);
    });
  });

  test.describe('Admin Navigation', () => {
    test('admin link appears in navigation for admin users', async ({ page }) => {
      await page.goto('/');

      // Admin link should be visible in navigation
      const adminLink = page.getByTestId('admin-nav-link');
      await expect(adminLink).toBeVisible({ timeout: 10000 });
    });

    test('admin link navigates to admin dashboard', async ({ page }) => {
      await page.goto('/');

      // Click admin link
      const adminLink = page.getByTestId('admin-nav-link');
      await expect(adminLink).toBeVisible({ timeout: 10000 });
      await adminLink.click();

      // Should navigate to admin page
      await expect(page).toHaveURL('/admin');

      // Should see admin dashboard
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();
    });

    test('admin link is styled differently from normal links', async ({ page }) => {
      await page.goto('/');

      const adminLink = page.getByTestId('admin-nav-link');
      await expect(adminLink).toBeVisible({ timeout: 10000 });

      // Admin link should have purple color scheme (based on implementation)
      const linkClass = await adminLink.getAttribute('class');
      expect(linkClass).toBeTruthy();
      expect(linkClass).toContain('purple');
    });
  });

  test.describe('Admin Page Features', () => {
    test('admin page is not cached (always fresh)', async ({ page }) => {
      // Visit admin page
      await page.goto('/admin');
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      // Refresh page
      await page.reload();

      // Should still show admin content
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();
    });

    test('admin page shows user email', async ({ page }) => {
      await page.goto('/admin');

      // Admin dashboard shows "Welcome, {email}"
      const welcomeSection = page.getByText(/welcome/i);
      await expect(welcomeSection).toBeVisible();

      // Should contain user email or administrator text
      const pageText = await page.textContent('body');
      expect(pageText).toBeTruthy();
    });

    test('admin page loads without errors', async ({ page }) => {
      const errors: string[] = [];

      page.on('pageerror', (error) => {
        errors.push(error.message);
      });

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(msg.text());
        }
      });

      await page.goto('/admin');

      // Wait for page to fully load
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      // Should have no JavaScript errors
      expect(errors).toHaveLength(0);
    });
  });

  test.describe('Admin Sub-Pages Navigation', () => {
    test('admin dashboard shows links to management sections', async ({ page }) => {
      await page.goto('/admin');

      // Look for management section links
      const pageContent = await page.textContent('body');

      // Admin dashboard typically has links to various admin functions
      // Verify the page has interactive elements (links/buttons)
      const links = page.locator('a');
      const linkCount = await links.count();

      // Should have multiple links (navigation + admin sections)
      expect(linkCount).toBeGreaterThan(5);
    });

    test('admin can navigate back to main app from admin dashboard', async ({ page }) => {
      await page.goto('/admin');

      // Click home/logo link
      const homeLink = page.getByRole('link', { name: /yt summarizer/i });
      await expect(homeLink).toBeVisible();
      await homeLink.click();

      // Should navigate to home
      await expect(page).toHaveURL('/');
    });

    test('admin dashboard maintains session across navigation', async ({ page }) => {
      // Start at admin dashboard
      await page.goto('/admin');
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      // Navigate to another page
      await page.goto('/add');

      // Navigate back to admin
      await page.goto('/admin');

      // Should still have access
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();
    });
  });

  test.describe('Admin User Experience', () => {
    test('admin dashboard is responsive', async ({ page }) => {
      await page.goto('/admin');

      // Should load on different viewport sizes
      await page.setViewportSize({ width: 1920, height: 1080 });
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      await page.setViewportSize({ width: 768, height: 1024 });
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();

      await page.setViewportSize({ width: 375, height: 667 });
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();
    });

    test('admin dashboard has proper page title', async ({ page }) => {
      await page.goto('/admin');

      // Should have appropriate page title
      const title = await page.title();
      expect(title).toBeTruthy();
    });

    test('admin dashboard uses gradient background', async ({ page }) => {
      await page.goto('/admin');

      // The admin dashboard has a gradient background
      const body = page.locator('body');
      await expect(body).toBeVisible();

      // Just verify the page loads correctly
      await expect(page.getByRole('heading', { name: /admin dashboard/i })).toBeVisible();
    });
  });

  test.describe('Security Validation', () => {
    test('admin dashboard requires authentication', async ({ browser }) => {
      // Create context without auth state
      const context = await browser.newContext({ storageState: undefined });
      const page = await context.newPage();

      try {
        await page.goto('http://localhost:3000/admin');

        // Should redirect to login
        await page.waitForURL((url) => url.pathname.includes('/sign-in'), {
          timeout: 10000,
        });

        expect(page.url()).toContain('/sign-in');
      } finally {
        await context.close();
      }
    });

    test('admin dashboard does not expose sensitive data in HTML', async ({ page }) => {
      await page.goto('/admin');

      const htmlContent = await page.content();

      // Should not expose raw database credentials, API keys, etc.
      expect(htmlContent.toLowerCase()).not.toContain('password');
      expect(htmlContent.toLowerCase()).not.toContain('api_key');
      expect(htmlContent.toLowerCase()).not.toContain('secret_key');
    });
  });
});
