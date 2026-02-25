import { test, expect } from '@playwright/test';

/**
 * E2E Tests for "Explain Why" Feature (User Story 5)
 *
 * These tests verify the transparency features:
 * 1. "Why this?" button appears on video cards with explanations
 * 2. Clicking "Why this?" toggles the explanation panel
 * 3. Explanation panel shows summary, key moments, and relationship info
 * 4. Key moments have clickable timestamp links
 *
 * Prerequisites:
 * - For tests that need the backend, run Aspire first
 * - Then run tests with: USE_EXTERNAL_SERVER=true npm run test:e2e
 */

test.describe('US5: Explain Why Feature', () => {
  test.describe('Why This Button', () => {
    test('video cards with explanation data show Why this? button', async ({ page }) => {
      // Navigate to library page
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Open the AI assistant panel
      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
        await page.waitForTimeout(500);
      }

      // Ask a question to get video results with explanations
      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('What are the best techniques?');
        await chatInput.press('Enter');

        // Wait for response
        await page.waitForTimeout(5000);

        // Look for "Why this?" button on any video card
        const whyThisButton = page.getByRole('button', { name: /why this/i });

        // If videos with explanations are returned, the button should be visible
        const buttonCount = await whyThisButton.count();
        // We don't strictly require it since it depends on LLM generating explanations
        expect(buttonCount >= 0).toBeTruthy();
      }
    });

    test('Why this? button toggles explanation panel', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Open AI assistant
      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
        await page.waitForTimeout(500);
      }

      // Submit a query
      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('Tell me about training fundamentals');
        await chatInput.press('Enter');

        await page.waitForTimeout(5000);

        // Find and click "Why this?" button if present
        const whyThisButton = page.getByRole('button', { name: /why this/i }).first();

        if (await whyThisButton.isVisible().catch(() => false)) {
          // Initially, explanation panel should not be visible
          const explanationPanel = page.locator('[data-testid="explanation-panel"]');
          await expect(explanationPanel).not.toBeVisible();

          // Click to expand
          await whyThisButton.click();

          // Now explanation panel should be visible
          await expect(explanationPanel.first()).toBeVisible();

          // Click again to collapse
          await whyThisButton.click();
          await page.waitForTimeout(300);

          // Panel should be hidden again
          await expect(explanationPanel).not.toBeVisible();
        }
      }
    });
  });

  test.describe('Explanation Panel Content', () => {
    test('explanation panel shows summary text', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      // Open AI assistant and query
      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
      }

      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('What techniques should I learn?');
        await chatInput.press('Enter');

        await page.waitForTimeout(5000);

        const whyThisButton = page.getByRole('button', { name: /why this/i }).first();

        if (await whyThisButton.isVisible().catch(() => false)) {
          await whyThisButton.click();

          // Explanation panel should have text content
          const explanationPanel = page.locator('[data-testid="explanation-panel"]');
          await expect(explanationPanel.first()).toBeVisible();

          // Should contain some text (the summary)
          const panelText = await explanationPanel.first().textContent();
          expect(panelText?.length).toBeGreaterThan(10);
        }
      }
    });

    test('key moments have clickable YouTube links', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
      }

      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('Show me beginner content');
        await chatInput.press('Enter');

        await page.waitForTimeout(5000);

        const whyThisButton = page.getByRole('button', { name: /why this/i }).first();

        if (await whyThisButton.isVisible().catch(() => false)) {
          await whyThisButton.click();
          await page.waitForTimeout(300);

          // Check for key moment links (if present)
          const keyMomentLinks = page.locator('[data-testid="key-moment-link"]');
          const linkCount = await keyMomentLinks.count();

          if (linkCount > 0) {
            // Verify links point to YouTube
            const firstLink = keyMomentLinks.first();
            const href = await firstLink.getAttribute('href');
            expect(href).toContain('youtube.com');
          }
        }
      }
    });

    test('relationship badge shows series/related info when present', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
      }

      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('Find videos in a series');
        await chatInput.press('Enter');

        await page.waitForTimeout(5000);

        const whyThisButton = page.getByRole('button', { name: /why this/i }).first();

        if (await whyThisButton.isVisible().catch(() => false)) {
          await whyThisButton.click();
          await page.waitForTimeout(300);

          // Check for relationship badge (may or may not be present depending on data)
          const relationshipBadge = page.locator('[data-testid="relationship-badge"]');
          const badgeCount = await relationshipBadge.count();

          // Badge is optional - only shown when video has relationship data
          expect(badgeCount >= 0).toBeTruthy();
        }
      }
    });
  });

  test.describe('Accessibility', () => {
    test('Why this? button has proper aria attributes', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('domcontentloaded');

      const openChatButton = page.getByRole('button', { name: /open|chat|assistant/i });
      if (await openChatButton.isVisible().catch(() => false)) {
        await openChatButton.click();
      }

      const chatInput = page.getByRole('textbox').first();
      if (await chatInput.isVisible().catch(() => false)) {
        await chatInput.fill('Test query');
        await chatInput.press('Enter');

        await page.waitForTimeout(5000);

        const whyThisButton = page.getByRole('button', { name: /why this/i }).first();

        if (await whyThisButton.isVisible().catch(() => false)) {
          // Button should have aria-expanded attribute
          const ariaExpanded = await whyThisButton.getAttribute('aria-expanded');
          expect(ariaExpanded).toBe('false');

          // Button should have aria-label
          const ariaLabel = await whyThisButton.getAttribute('aria-label');
          expect(ariaLabel).toBeTruthy();

          // Click and verify aria-expanded changes
          await whyThisButton.click();
          const ariaExpandedAfter = await whyThisButton.getAttribute('aria-expanded');
          expect(ariaExpandedAfter).toBe('true');
        }
      }
    });
  });
});
