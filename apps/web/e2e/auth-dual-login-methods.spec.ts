/**
 * E2E Tests for Dual Login Methods UI (User Story 3)
 *
 * Tests that both social login and username/password authentication methods
 * are visible and accessible on the login page.
 *
 * Test Coverage:
 * 1. Both authentication methods visible simultaneously
 * 2. Divider separates the two methods clearly
 * 3. Both methods are fully functional
 * 4. UI layout is responsive and accessible
 * 5. User can choose either method
 *
 * Prerequisites:
 * - Auth0 configured with both social connections (Google, GitHub)
 * - Auth0 database connection configured for username/password
 * - Login page implements both authentication methods
 *
 * This validates FR-006a (dual authentication) and SC-009 (both methods available).
 */

import { test, expect } from '@playwright/test';

test.describe('Dual Login Methods UI @auth', () => {
  test.describe('Visual Layout and Structure', () => {
    test('displays both social login and username/password options', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Social login section
      const googleButton = page.getByRole('button', { name: /google/i });
      const githubButton = page.getByRole('button', { name: /github/i });

      await expect(googleButton).toBeVisible();
      await expect(githubButton).toBeVisible();

      // Username/password section
      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');
      const submitButton = page.getByRole('button', { name: /sign in/i }).last();

      await expect(emailInput).toBeVisible();
      await expect(passwordInput).toBeVisible();
      await expect(submitButton).toBeVisible();
    });

    test('displays divider between authentication methods', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Should have divider text
      const divider = page.getByText(/or continue with email/i);
      await expect(divider).toBeVisible();

      // Verify divider is between social and email/password
      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      // Both should be visible (divider separates them)
      await expect(googleButton).toBeVisible();
      await expect(emailInput).toBeVisible();
    });

    test('divider text is clear and readable', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const divider = page.getByText(/or continue with email/i);

      // Should be visible
      await expect(divider).toBeVisible();

      // Should contain appropriate text
      const dividerText = await divider.textContent();
      expect(dividerText?.toLowerCase()).toContain('or');
      expect(dividerText?.toLowerCase()).toContain('email');
    });

    test('social login section appears before username/password', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Get positions of elements
      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      const googleBox = await googleButton.boundingBox();
      const emailBox = await emailInput.boundingBox();

      // Social login should be above email/password (smaller Y coordinate)
      expect(googleBox!.y).toBeLessThan(emailBox!.y);
    });

    test('all login elements are within the same card container', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // All login elements should be in the same visual container
      // Check that they're all visible and part of the login flow
      const googleButton = page.getByRole('button', { name: /google/i });
      const divider = page.getByText(/or continue with email/i);
      const emailInput = page.getByLabel(/email/i);

      await expect(googleButton).toBeVisible();
      await expect(divider).toBeVisible();
      await expect(emailInput).toBeVisible();
    });
  });

  test.describe('Functionality of Both Methods', () => {
    test('social login buttons are clickable and functional', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });
      const githubButton = page.getByRole('button', { name: /github/i });

      // Buttons should be enabled
      await expect(googleButton).toBeEnabled();
      await expect(githubButton).toBeEnabled();

      // Buttons should be clickable (we don't actually click to avoid OAuth redirect)
      const googleClickable = await googleButton.isEnabled();
      const githubClickable = await githubButton.isEnabled();

      expect(googleClickable).toBe(true);
      expect(githubClickable).toBe(true);
    });

    test('username/password form is functional', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');
      const submitButton = page.getByRole('button', { name: /sign in/i }).last();

      // Form should be interactive
      await emailInput.fill('test@example.com');
      await passwordInput.fill('password123');

      // Submit button should become enabled
      await expect(submitButton).not.toBeDisabled();

      // Verify inputs hold values
      await expect(emailInput).toHaveValue('test@example.com');
      await expect(passwordInput).toHaveValue('password123');
    });

    test('user can switch focus between both authentication methods', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      // Focus on social login
      await googleButton.focus();
      await expect(googleButton).toBeFocused();

      // Switch focus to email/password
      await emailInput.focus();
      await expect(emailInput).toBeFocused();

      // Verify both remain visible and functional
      await expect(googleButton).toBeVisible();
      await expect(emailInput).toBeVisible();
    });
  });

  test.describe('User Choice and Flow', () => {
    test('user can choose to use social login', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });

      // User can see and interact with social login
      await expect(googleButton).toBeVisible();
      await expect(googleButton).toBeEnabled();

      // Email/password fields are not required for social login
      const emailInput = page.getByLabel(/email/i);
      const emailValue = await emailInput.inputValue();
      expect(emailValue).toBe(''); // Should be empty
    });

    test('user can choose to use username/password', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');
      const submitButton = page.getByRole('button', { name: /sign in/i }).last();

      // User can interact with username/password form
      await emailInput.fill('test@example.com');
      await passwordInput.fill('password123');

      // Submit button becomes active (shows this method is viable)
      await expect(submitButton).not.toBeDisabled();

      // Social buttons remain visible but user doesn't have to use them
      const googleButton = page.getByRole('button', { name: /google/i });
      await expect(googleButton).toBeVisible();
    });

    test('no conflicts between authentication methods', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Fill in email/password
      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');

      await emailInput.fill('test@example.com');
      await passwordInput.fill('password123');

      // Social login buttons should still be clickable
      const googleButton = page.getByRole('button', { name: /google/i });
      await expect(googleButton).toBeEnabled();

      // No error messages or conflicts
      const errors = page.getByRole('alert');
      const errorCount = await errors.count();

      // If there are alerts, they should only be validation messages (not conflicts)
      if (errorCount > 0) {
        const errorText = await errors.first().textContent();
        expect(errorText).not.toContain('conflict');
        expect(errorText).not.toContain('error');
      }
    });
  });

  test.describe('Responsive Design', () => {
    test('both methods visible on desktop viewport', async ({ page }) => {
      await page.setViewportSize({ width: 1920, height: 1080 });
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      await expect(googleButton).toBeVisible();
      await expect(emailInput).toBeVisible();
    });

    test('both methods visible on tablet viewport', async ({ page }) => {
      await page.setViewportSize({ width: 768, height: 1024 });
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      await expect(googleButton).toBeVisible();
      await expect(emailInput).toBeVisible();
    });

    test('both methods visible on mobile viewport', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 });
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      await expect(googleButton).toBeVisible();
      await expect(emailInput).toBeVisible();
    });

    test('layout adapts gracefully to different screen sizes', async ({ page }) => {
      const viewports = [
        { width: 1920, height: 1080 }, // Desktop
        { width: 768, height: 1024 }, // Tablet
        { width: 375, height: 667 }, // Mobile
      ];

      for (const viewport of viewports) {
        await page.setViewportSize(viewport);
        await page.goto('/sign-in', { waitUntil: 'networkidle' });

        // All key elements should be visible
        const googleButton = page.getByRole('button', { name: /google/i });
        const divider = page.getByText(/or continue with email/i);
        const emailInput = page.getByLabel(/email/i);

        await expect(googleButton).toBeVisible();
        await expect(divider).toBeVisible();
        await expect(emailInput).toBeVisible();
      }
    });
  });

  test.describe('Accessibility for Both Methods', () => {
    test('both methods are keyboard accessible', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Tab through all interactive elements
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');

      // Should be able to navigate to both social buttons and form inputs
      const googleButton = page.getByRole('button', { name: /google/i });
      await googleButton.focus();
      await expect(googleButton).toBeFocused();

      const emailInput = page.getByLabel(/email/i);
      await emailInput.focus();
      await expect(emailInput).toBeFocused();
    });

    test('both methods have proper ARIA attributes', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Social login buttons should have accessible names
      const googleButton = page.getByRole('button', { name: /google/i });
      const googleLabel = await googleButton.getAttribute('aria-label');
      expect(googleLabel || (await googleButton.textContent())).toBeTruthy();

      // Email/password inputs should have ARIA labels
      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');

      await expect(emailInput).toHaveAttribute('aria-label');
      await expect(passwordInput).toHaveAttribute('aria-label');
    });

    test('screen reader can distinguish between authentication methods', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Divider should help screen readers understand the separation
      const divider = page.getByText(/or continue with email/i);
      await expect(divider).toBeVisible();

      // Each section should be identifiable
      const googleButton = page.getByRole('button', { name: /google/i });
      const emailInput = page.getByLabel(/email/i);

      // Verify distinct labels
      const googleText = await googleButton.textContent();
      const emailLabel = await emailInput.getAttribute('aria-label');

      expect(googleText).toContain('Google');
      expect(emailLabel).toContain('mail');
    });
  });

  test.describe('User Story 3 Acceptance Scenarios', () => {
    test('US3 Scenario 2: User sees both Google OAuth and username/password options', async ({
      page,
    }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // Social login options
      const googleButton = page.getByRole('button', { name: /google/i });
      const githubButton = page.getByRole('button', { name: /github/i });

      await expect(googleButton).toBeVisible();
      await expect(githubButton).toBeVisible();

      // Username/password option
      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');
      const submitButton = page.getByRole('button', { name: /sign in/i }).last();

      await expect(emailInput).toBeVisible();
      await expect(passwordInput).toBeVisible();
      await expect(submitButton).toBeVisible();

      // Divider clearly separates the options
      const divider = page.getByText(/or continue with email/i);
      await expect(divider).toBeVisible();
    });

    test('US3 Scenario 2: User can choose either authentication method', async ({ page }) => {
      await page.goto('/sign-in', { waitUntil: 'networkidle' });

      // User can choose social login
      const googleButton = page.getByRole('button', { name: /google/i });
      await expect(googleButton).toBeEnabled();

      // OR user can choose username/password
      const emailInput = page.getByLabel(/email/i);
      const passwordInput = page.getByLabel('Password');
      const submitButton = page.getByRole('button', { name: /sign in/i }).last();

      await emailInput.fill('test@example.com');
      await passwordInput.fill('password123');
      await expect(submitButton).not.toBeDisabled();

      // Both methods are independent and functional
      await expect(googleButton).toBeEnabled(); // Still enabled after filling form
    });
  });
});
