import { test, expect } from '@playwright/test';

/**
 * E2E Tests for Synthesis Feature UI (User Story 6)
 *
 * These tests verify the synthesis UI COMPONENTS render correctly:
 * 1. Chat input for synthesis requests
 * 2. Response area displays content
 * 3. Basic interaction flows work
 *
 * NOTE: LLM response validation is done in synthesis-api.spec.ts
 * which tests the API directly. These UI tests focus on component rendering
 * and user interaction patterns only.
 *
 * Prerequisites:
 * - Aspire backend running
 * - Run with: USE_EXTERNAL_SERVER=true npx playwright test synthesis
 */

test.describe('US6: Synthesis Feature UI', () => {
  // Skip unless backend is running
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  test.describe('Chat Interface for Synthesis', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
    });

    test('chat input accepts synthesis requests', async ({ page }) => {
      // Find the chat input
      const chatInput = page.getByRole('textbox').first();
      await expect(chatInput).toBeVisible({ timeout: 5000 });
      
      // Type a learning path request
      await chatInput.fill('Create a learning path for Python programming');
      await expect(chatInput).toHaveValue('Create a learning path for Python programming');
      
      // Submit the request
      await chatInput.press('Enter');
      
      // Verify a response area appears (loading state or actual response)
      const responseArea = page.locator('[class*="message" i], [class*="response" i], [class*="assistant" i]');
      
      // Wait for agent to start responding
      await expect(responseArea.first()).toBeVisible({ timeout: 30000 });
    });

    test('can submit watch list request', async ({ page }) => {
      const chatInput = page.getByRole('textbox').first();
      await expect(chatInput).toBeVisible({ timeout: 5000 });
      
      await chatInput.fill('Give me a watch list for Python OOP videos');
      await chatInput.press('Enter');
      
      // Wait for response to appear
      await page.waitForTimeout(15000);
      
      // The page should show some response content
      const responseContent = page.locator('[class*="message" i], [class*="card" i]');
      await expect(responseContent.first()).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Component Rendering', () => {
    test('library page loads without critical console errors', async ({ page }) => {
      const errors: string[] = [];
      page.on('console', msg => {
        if (msg.type() === 'error') {
          const text = msg.text().toLowerCase();
          // Filter out expected/non-critical errors
          if (!text.includes('failed to fetch') && 
              !text.includes('net::err') &&
              !text.includes('dev mode') &&
              !text.includes('hydrat') &&
              !text.includes('warning') &&
              !text.includes('cors') &&
              !text.includes('favicon')) {
            errors.push(msg.text());
          }
        }
      });
      
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);
      
      // Should have no critical console errors
      expect(errors.length).toBe(0);
    });

    test('chat interface is accessible on library page', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      // Chat input should be visible
      const chatInput = page.getByRole('textbox').first();
      await expect(chatInput).toBeVisible({ timeout: 5000 });
      
      // Should have accessible label or placeholder
      const placeholder = await chatInput.getAttribute('placeholder');
      expect(placeholder).toBeTruthy();
    });
  });
});
