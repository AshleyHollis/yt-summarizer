/**
 * E2E Tests for Authenticated User Accessing Protected Pages (User Story 4)
 *
 * Tests that authenticated users can successfully access protected routes
 * and their session persists across navigation.
 *
 * Test Coverage:
 * 1. Authenticated users can access protected routes
 * 2. Session persists across page navigation
 * 3. Session persists across page refreshes
 * 4. Protected content is displayed correctly
 * 5. User profile information is visible
 * 6. Authenticated navigation is available
 *
 * Prerequisites:
 * - Auth setup (auth.setup.ts) has run successfully
 * - Normal user auth state exists in playwright/.auth/user.json
 *
 * Implementation: T059 (Create E2E test for authenticated user accessing protected page)
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Authenticated User Accessing Protected Pages @auth', () => {
  /**
   * Skip all tests if auth is not configured
   */
  test.skip(
    () => {
      const authFile = path.join(__dirname, '../playwright/.auth/user.json');
      return !fs.existsSync(authFile);
    },
    'Auth0 not configured - set AUTH0_USER_TEST_EMAIL and AUTH0_USER_TEST_PASSWORD to run user tests'
  );

  test.describe('Access to Protected Routes', () => {
    test('authenticated user can access home page', async ({ page }) => {
      await page.goto('/');

      // Should successfully load home page
      await expect(page).toHaveURL('/');

      // Page should be visible
      const body = page.locator('body');
      await expect(body).toBeVisible();
    });

    test('authenticated user can access /add page', async ({ page }) => {
      await page.goto('/add');

      // Should successfully load page
      await expect(page).toHaveURL('/add');

      // Page should not redirect to login
      const currentUrl = page.url();
      expect(currentUrl).not.toContain('/login');
    });

    test('authenticated user can access /library page', async ({ page }) => {
      await page.goto('/library');

      // Should successfully load page
      await expect(page).toHaveURL('/library');

      // Page should not redirect to login
      const currentUrl = page.url();
      expect(currentUrl).not.toContain('/login');
    });

    test('authenticated user without admin role cannot access /admin', async ({ page }) => {
      await page.goto('/admin');

      // Should redirect to access-denied (unless user has admin role)
      await page.waitForURL(
        (url) => url.pathname.includes('/access-denied') || url.pathname.includes('/admin'),
        { timeout: 10000 }
      );

      const currentUrl = page.url();

      // If user landed on admin page, they have admin role (different test file handles this)
      if (currentUrl.includes('/admin') && !currentUrl.includes('/access-denied')) {
        test.skip(true, 'Test user has admin role - see rbac-admin-access.spec.ts instead');
      }

      // Normal users should be denied
      expect(currentUrl).toContain('/access-denied');
    });
  });

  test.describe('Session Persistence', () => {
    test('session persists across page navigation', async ({ page }) => {
      // Start at home page
      await page.goto('/');

      // Verify user is authenticated by checking for user profile
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate to another page
      await page.goto('/add');

      // User should still be authenticated
      await expect(userProfile).toBeVisible();

      // Navigate to library
      await page.goto('/library');

      // User should still be authenticated
      await expect(userProfile).toBeVisible();
    });

    test('session persists across page refresh', async ({ page }) => {
      await page.goto('/');

      // Verify user is authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Refresh the page
      await page.reload();

      // User should still be authenticated after refresh
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });

    test('session persists across multiple refreshes', async ({ page }) => {
      await page.goto('/');

      // Verify user is authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Refresh multiple times
      for (let i = 0; i < 3; i++) {
        await page.reload();
        await expect(userProfile).toBeVisible({ timeout: 10000 });
      }
    });

    test('session persists when navigating back and forward', async ({ page }) => {
      // Navigate to home
      await page.goto('/');
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Navigate to add
      await page.goto('/add');
      await expect(userProfile).toBeVisible();

      // Go back
      await page.goBack();
      await expect(page).toHaveURL('/');
      await expect(userProfile).toBeVisible();

      // Go forward
      await page.goForward();
      await expect(page).toHaveURL('/add');
      await expect(userProfile).toBeVisible();
    });
  });

  test.describe('User Profile Visibility', () => {
    test('authenticated user sees user profile in navigation', async ({ page }) => {
      await page.goto('/');

      // User profile should be visible
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });
    });

    test('user profile displays user email', async ({ page }) => {
      await page.goto('/');

      // User profile should show email
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Should contain email text (format: user@domain)
      const profileText = await userProfile.textContent();
      expect(profileText).toBeTruthy();
      expect(profileText).toMatch(/@/);
    });

    test('user profile shows logout button', async ({ page }) => {
      await page.goto('/');

      // Should see logout button
      const logoutButton = page.getByRole('button', { name: /sign out|log out/i });
      await expect(logoutButton).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('Authenticated Navigation', () => {
    test('authenticated user sees standard navigation links', async ({ page }) => {
      await page.goto('/');

      // Should see standard navigation links
      const addLink = page.getByRole('link', { name: /add/i }).first();
      await expect(addLink).toBeVisible({ timeout: 10000 });

      const libraryLink = page.getByRole('link', { name: /library/i });
      await expect(libraryLink).toBeVisible();
    });

    test('authenticated user without admin role does not see admin link', async ({ page }) => {
      await page.goto('/');

      // Admin link should not be visible for normal users
      const adminLink = page.getByTestId('admin-nav-link');
      const adminLinkCount = await adminLink.count();

      // If admin link is visible, user has admin role (different test)
      if (adminLinkCount > 0) {
        const isVisible = await adminLink.isVisible();
        if (isVisible) {
          test.skip(true, 'Test user has admin role - see rbac-navigation.spec.ts instead');
        }
      }

      expect(adminLinkCount).toBe(0);
    });

    test('navigation links work correctly', async ({ page }) => {
      await page.goto('/');

      // Click Add link
      const addLink = page.getByRole('link', { name: /add/i }).first();
      await addLink.click();
      await expect(page).toHaveURL('/add');

      // Go back home
      await page.goto('/');

      // Click Library link
      const libraryLink = page.getByRole('link', { name: /library/i });
      await libraryLink.click();
      await expect(page).toHaveURL('/library');
    });
  });

  test.describe('Protected Content Display', () => {
    test('protected pages display content correctly', async ({ page }) => {
      await page.goto('/');

      // Page should have content
      const body = page.locator('body');
      await expect(body).toBeVisible();

      const bodyText = await body.textContent();
      expect(bodyText).toBeTruthy();
      expect(bodyText!.length).toBeGreaterThan(100);
    });

    test('protected pages load without JavaScript errors', async ({ page }) => {
      const errors: string[] = [];

      page.on('pageerror', (error) => {
        errors.push(error.message);
      });

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(msg.text());
        }
      });

      await page.goto('/');

      // Wait for page to fully load
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Should have no JavaScript errors
      expect(errors).toHaveLength(0);
    });

    test('protected pages have proper page titles', async ({ page }) => {
      // Home page
      await page.goto('/');
      const homeTitle = await page.title();
      expect(homeTitle).toBeTruthy();

      // Add page
      await page.goto('/add');
      const addTitle = await page.title();
      expect(addTitle).toBeTruthy();

      // Library page
      await page.goto('/library');
      const libraryTitle = await page.title();
      expect(libraryTitle).toBeTruthy();
    });
  });

  test.describe('API Access', () => {
    test('authenticated user can access /api/auth/me endpoint', async ({ page }) => {
      // Make authenticated request to /me endpoint
      const response = await page.request.get('http://localhost:3000/api/auth/me');

      // Should return 200 OK
      expect(response.status()).toBe(200);

      // Should return user data
      const data = await response.json();
      expect(data).toBeTruthy();
      expect(data.email).toBeTruthy();
    });

    test('authenticated user data is correct in /api/auth/me', async ({ page }) => {
      const response = await page.request.get('http://localhost:3000/api/auth/me');
      expect(response.status()).toBe(200);

      const userData = await response.json();

      // Should have expected user fields
      expect(userData).toHaveProperty('email');
      expect(userData).toHaveProperty('sub');

      // Email should match test user
      expect(userData.email).toContain('@');
    });
  });

  test.describe('Security Validation', () => {
    test('authenticated session is properly secured', async ({ page }) => {
      await page.goto('/');

      // User should be authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Session cookies should be HttpOnly and Secure (cannot check directly in E2E)
      // But we can verify the session works correctly
      const cookies = await page.context().cookies();

      // Should have auth-related cookies
      const authCookies = cookies.filter(c =>
        c.name.includes('auth') ||
        c.name.includes('session') ||
        c.name.startsWith('appSession')
      );

      expect(authCookies.length).toBeGreaterThan(0);
    });

    test('authenticated pages do not expose sensitive data in HTML', async ({ page }) => {
      await page.goto('/');

      const htmlContent = await page.content();

      // Should not expose raw tokens, passwords, secrets
      expect(htmlContent.toLowerCase()).not.toContain('access_token');
      expect(htmlContent.toLowerCase()).not.toContain('refresh_token');
      expect(htmlContent.toLowerCase()).not.toContain('client_secret');
    });
  });

  test.describe('User Experience', () => {
    test('authenticated pages are responsive', async ({ page }) => {
      await page.goto('/');

      // Test on mobile viewport
      await page.setViewportSize({ width: 375, height: 667 });
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Test on tablet
      await page.setViewportSize({ width: 768, height: 1024 });
      await expect(userProfile).toBeVisible();

      // Test on desktop
      await page.setViewportSize({ width: 1920, height: 1080 });
      await expect(userProfile).toBeVisible();
    });

    test('page load performance is acceptable', async ({ page }) => {
      const startTime = Date.now();

      await page.goto('/');

      // Wait for user profile to be visible (page fully loaded)
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      const loadTime = Date.now() - startTime;

      // Page should load in reasonable time (< 5 seconds)
      expect(loadTime).toBeLessThan(5000);
    });
  });

  test.describe('Logout Functionality', () => {
    test('authenticated user can sign out', async ({ page }) => {
      await page.goto('/');

      // Verify user is authenticated
      const userProfile = page.getByTestId('user-profile');
      await expect(userProfile).toBeVisible({ timeout: 10000 });

      // Click logout button
      const logoutButton = page.getByRole('button', { name: /sign out|log out/i });
      await expect(logoutButton).toBeVisible();
      await logoutButton.click();

      // Should redirect to login or home page
      await page.waitForURL(
        (url) => url.pathname === '/' || url.pathname.includes('/login'),
        { timeout: 10000 }
      );

      // User profile should no longer be visible
      const userProfileAfterLogout = page.getByTestId('user-profile');
      const profileCount = await userProfileAfterLogout.count();
      expect(profileCount).toBe(0);
    });
  });
});
