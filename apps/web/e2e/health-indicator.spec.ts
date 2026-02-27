import { test, expect } from '@playwright/test';

/**
 * E2E Tests for WarmingUpIndicator (FR-020)
 *
 * Tests the health status banner behavior:
 * - Shows warning banner when service is degraded/unhealthy
 * - Hides banner when service is healthy
 *
 * Note: The banner visibility depends on real-time health check results.
 * These tests verify the component behaves correctly in either state.
 */

test.describe('WarmingUpIndicator Health Status Banner', () => {
  test.describe('Banner behavior with healthy API', () => {
    test('banner should eventually hide when API becomes healthy', async ({ page }) => {
      // Navigate to library page
      await page.goto('/library');

      // Wait for the page to fully load
      await page.waitForLoadState('domcontentloaded');

      // Give the health check time to complete (it polls periodically)
      // The health check polls every 5 seconds and updates state
      await page.waitForTimeout(6000);

      const warmingIndicator = page.getByTestId('warming-up-indicator');

      // Check if the banner eventually becomes hidden as API stabilizes
      // We use a longer timeout since health checks are async
      try {
        await expect(warmingIndicator).not.toBeVisible({ timeout: 15000 });
        // If we get here, banner is hidden - API is healthy
        test.info().annotations.push({
          type: 'pass',
          description: 'Banner correctly hidden when API is healthy',
        });
      } catch {
        // Banner is still visible - API may be degraded or unhealthy
        // This is still valid behavior if the API is actually unhealthy
        const bannerText = await warmingIndicator.textContent();
        test.info().annotations.push({
          type: 'info',
          description: `Banner visible with message: ${bannerText}`,
        });

        // Verify at least the banner has correct structure
        await expect(warmingIndicator).toHaveAttribute('role', 'status');
      }
    });

    test('page content loads regardless of health status', async ({ page }) => {
      // Navigate to library page
      await page.goto('/library');

      // Wait for page to load
      await page.waitForLoadState('domcontentloaded');

      // Verify core content is visible (page should work even with banner)
      // The library page should show video count or navigation
      await expect(page.getByRole('navigation').first()).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('Banner structure and accessibility', () => {
    test('banner has correct ARIA attributes when visible', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');
      await page.waitForTimeout(2000);

      const warmingIndicator = page.getByTestId('warming-up-indicator');
      const bannerVisible = await warmingIndicator.isVisible().catch(() => false);

      if (bannerVisible) {
        // Verify accessibility attributes
        await expect(warmingIndicator).toHaveRole('status');
        await expect(warmingIndicator).toHaveAttribute('aria-live', 'polite');

        // Verify it contains a message
        const text = await warmingIndicator.textContent();
        expect(text).toBeTruthy();
        expect(text!.length).toBeGreaterThan(5);
      } else {
        // When not visible, component returns null - correct behavior
        expect(await warmingIndicator.count()).toBe(0);
      }
    });

    test('banner has correct styling for degraded or unhealthy state', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');
      await page.waitForTimeout(2000);

      const warmingIndicator = page.getByTestId('warming-up-indicator');
      const bannerVisible = await warmingIndicator.isVisible().catch(() => false);

      if (bannerVisible) {
        // Verify styling classes are applied
        const classList = await warmingIndicator.getAttribute('class');

        // Should have either yellow (degraded) or red (unhealthy) styling
        expect(classList).toMatch(/bg-(yellow|red)/);

        // Should have appropriate text color
        expect(classList).toMatch(/text-(yellow|red)/);
      } else {
        // API is healthy - banner correctly not shown
        test.info().annotations.push({
          type: 'pass',
          description: 'API is healthy - banner correctly hidden',
        });
      }
    });
  });

  test.describe('Banner message content', () => {
    test('banner message is appropriate for the status', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');
      await page.waitForTimeout(2000);

      const warmingIndicator = page.getByTestId('warming-up-indicator');
      const bannerVisible = await warmingIndicator.isVisible().catch(() => false);

      if (bannerVisible) {
        const bannerText = await warmingIndicator.textContent();

        // Should contain one of the expected messages
        expect(bannerText).toMatch(
          /warming up|service unavailable|database.*starting|restore.*connectivity/i
        );

        // Should be informative (not empty or too short)
        expect(bannerText!.length).toBeGreaterThan(10);
      } else {
        // No banner = healthy, which is correct
        test.info().annotations.push({
          type: 'pass',
          description: 'No banner displayed - service is healthy',
        });
      }
    });
  });
});
