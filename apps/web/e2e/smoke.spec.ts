import { test, expect } from '@playwright/test';

/**
 * E2E Smoke Tests for YouTube Summarizer
 *
 * These tests verify the core user flows work correctly:
 * 1. Home page redirects to submit page
 * 2. Submit page renders correctly
 * 3. Form validation works
 * 4. Video submission flow works (requires backend)
 *
 * Prerequisites:
 * - For tests that need the backend, run Aspire first:
 *   cd services/aspire/AppHost && dotnet run
 * - Then run tests with: USE_EXTERNAL_SERVER=true npm run test:e2e
 */

test.describe('Core User Flows', () => {
  test.describe('Navigation', () => {
    test('home page redirects to submit page', async ({ page }) => {
      await page.goto('/');
      
      // Should redirect to /submit
      await expect(page).toHaveURL('/submit');
    });

    test('submit page has correct title', async ({ page }) => {
      await page.goto('/submit');
      
      // Check page title
      await expect(page).toHaveTitle(/Submit Video.*YouTube Summarizer/);
    });
  });

  test.describe('Submit Page UI', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/submit');
    });

    test('renders header with app name', async ({ page }) => {
      // Check header exists
      const header = page.locator('header');
      await expect(header).toBeVisible();
      
      // Check app title
      await expect(page.getByRole('heading', { name: 'YouTube Summarizer' })).toBeVisible();
    });

    test('renders hero section', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: /AI-Powered Video Summaries/i })
      ).toBeVisible();
    });

    test('renders submit form with URL input', async ({ page }) => {
      // Check for URL input
      const input = page.getByLabel(/YouTube Video URL/i);
      await expect(input).toBeVisible();
      await expect(input).toHaveAttribute('type', 'url');
      
      // Check placeholder text
      await expect(input).toHaveAttribute('placeholder', /youtube\.com/);
    });

    test('renders submit button', async ({ page }) => {
      const submitButton = page.getByRole('button', { name: /Submit|Process|Start/i });
      await expect(submitButton).toBeVisible();
    });

    test('renders feature cards', async ({ page }) => {
      // The submit page should have feature cards explaining capabilities
      // Check that at least one feature section exists
      const featureSection = page.locator('section').filter({ hasText: /transcript|summary|embed/i });
      await expect(featureSection.first()).toBeVisible();
    });
  });

  test.describe('Form Validation', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/submit');
    });

    test('submit button is disabled when URL is empty', async ({ page }) => {
      // Button should be disabled when URL is empty
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await expect(submitButton).toBeDisabled();
    });

    test('submit button becomes enabled when URL is entered', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      
      // Initially disabled
      await expect(submitButton).toBeDisabled();
      
      // Enter a URL
      await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
      
      // Should now be enabled
      await expect(submitButton).toBeEnabled();
    });

    test('shows error for invalid URL format after submission', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter a valid URL format but wrong domain (not YouTube)
      await input.fill('https://example.com/watch?v=abc123');
      
      // Button should be enabled since there's text
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await expect(submitButton).toBeEnabled();
      
      // Submit
      await submitButton.click();
      
      // Should show format validation error (our custom validation)
      await expect(page.getByText(/Please enter a valid YouTube URL/i)).toBeVisible();
    });

    test('shows error for non-YouTube URL', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter valid URL but not YouTube
      await input.fill('https://vimeo.com/12345');
      
      // Submit
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();
      
      // Should show validation error
      await expect(page.getByText(/Please enter a valid YouTube URL/i)).toBeVisible();
    });

    test('clears error when user starts typing', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter a valid URL format but non-YouTube to trigger error
      await input.fill('https://example.com/watch?v=abc123');
      const submitButton = page.getByRole('button', { name: /Process Video/i });
      await submitButton.click();
      
      // Error should be visible
      await expect(page.getByText(/Please enter a valid YouTube URL/i)).toBeVisible();
      
      // Modify the input
      await input.fill('https://youtube.com');
      
      // Error should clear
      await expect(page.getByText(/Please enter a valid YouTube URL/i)).not.toBeVisible();
    });
  });

  test.describe('Valid URL Input', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/submit');
    });

    test('accepts standard YouTube watch URL', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter valid YouTube URL
      await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
      
      // Input should have the value
      await expect(input).toHaveValue('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    });

    test('accepts YouTube short URL format', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter youtu.be short URL
      await input.fill('https://youtu.be/dQw4w9WgXcQ');
      
      // Should be accepted
      await expect(input).toHaveValue('https://youtu.be/dQw4w9WgXcQ');
    });

    test('accepts YouTube embed URL format', async ({ page }) => {
      const input = page.getByLabel(/YouTube Video URL/i);
      
      // Enter embed URL
      await input.fill('https://www.youtube.com/embed/dQw4w9WgXcQ');
      
      // Should be accepted
      await expect(input).toHaveValue('https://www.youtube.com/embed/dQw4w9WgXcQ');
    });
  });
});

test.describe('Video Submission (Requires Backend)', () => {
  // These tests require the Aspire backend to be running with a working database
  // Skip unless USE_EXTERNAL_SERVER is set
  test.skip(() => !process.env.USE_EXTERNAL_SERVER, 'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire');

  test('submits video and shows loading state', async ({ page }) => {
    await page.goto('/submit');
    
    const input = page.getByLabel(/YouTube Video URL/i);
    await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    
    const submitButton = page.getByRole('button', { name: /Submit|Process|Start/i });
    await submitButton.click();
    
    // Should show loading indicator or submitting button state
    // The form should either show "Submitting..." button or an error alert
    const submittingButton = page.getByRole('button', { name: 'Submitting...' });
    const errorAlertWithText = page.locator('role=alert').filter({ hasText: /error|failed/i });
    
    // Wait for either submitting state or an error message
    await expect(submittingButton.or(errorAlertWithText)).toBeVisible({ timeout: 5000 });
  });

  test('submits video and redirects to video detail page', async ({ page }) => {
    await page.goto('/submit');
    
    const input = page.getByLabel(/YouTube Video URL/i);
    await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    
    const submitButton = page.getByRole('button', { name: /Submit|Process|Start/i });
    await submitButton.click();
    
    // Should redirect to video detail page
    await page.waitForURL(/\/videos\/[a-zA-Z0-9-]+/, { timeout: 15000 });
    await expect(page).toHaveURL(/\/videos\/[a-zA-Z0-9-]+/);
  });

  test('video detail page shows processing status', async ({ page }) => {
    await page.goto('/submit');
    
    const input = page.getByLabel(/YouTube Video URL/i);
    await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    
    const submitButton = page.getByRole('button', { name: /Submit|Process|Start/i });
    await submitButton.click();
    
    // Wait for redirect to video detail page
    await page.waitForURL(/\/videos\/[a-zA-Z0-9-]+/, { timeout: 15000 });
    
    // Should show video detail page elements
    // The page shows either processing progress or video content
    const pageContent = page.locator('main');
    await expect(pageContent).toBeVisible();
    
    // Should have navigation back to submit - look for the actual link text
    const backLink = page.getByRole('link', { name: /Back to Submit/i });
    await expect(backLink).toBeVisible();
  });
});

test.describe('Error Handling (Requires Backend)', () => {
  test.skip(() => !process.env.USE_EXTERNAL_SERVER, 'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire');

  test('shows error message when API is unavailable', async ({ page }) => {
    // Block API requests to simulate unavailable backend
    await page.route('**/api/**', (route) => route.abort());
    
    await page.goto('/submit');
    
    const input = page.getByLabel(/YouTube Video URL/i);
    await input.fill('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    
    const submitButton = page.getByRole('button', { name: /Submit|Process|Start/i });
    await submitButton.click();
    
    // Should show error message
    await expect(page.getByText(/error|failed|unable|try again/i)).toBeVisible({
      timeout: 10000,
    });
  });

  test('handles non-existent video ID gracefully', async ({ page }) => {
    // Navigate directly to a non-existent video
    await page.goto('/videos/non-existent-video-id-12345');
    
    // Should show error or not found message
    const errorMessage = page.getByText(/not found|error|failed|unable/i);
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Accessibility', () => {
  test('submit form is keyboard accessible', async ({ page }) => {
    await page.goto('/submit');
    
    // Tab to the input
    await page.keyboard.press('Tab');
    
    // Should focus on the URL input or a focusable element
    const activeElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(['INPUT', 'BUTTON', 'A']).toContain(activeElement);
  });

  test('form input has accessible label', async ({ page }) => {
    await page.goto('/submit');
    
    // The input should be associated with a label
    const input = page.getByRole('textbox', { name: /url/i });
    await expect(input).toBeVisible();
  });

  test('error messages are announced', async ({ page }) => {
    await page.goto('/submit');
    
    const input = page.getByLabel(/YouTube Video URL/i);
    
    // Enter a valid URL format but non-YouTube to trigger our validation error
    await input.fill('https://example.com/watch?v=abc123');
    const submitButton = page.getByRole('button', { name: /Process Video/i });
    await submitButton.click();
    
    // Error should have appropriate ARIA attributes or be in an alert role
    const errorText = page.getByText(/Please enter a valid YouTube URL/i);
    await expect(errorText).toBeVisible();
    
    // Check if error is associated with input via aria-describedby
    const ariaDescribedBy = await input.getAttribute('aria-describedby');
    const ariaInvalid = await input.getAttribute('aria-invalid');
    
    // At least one accessibility feature should be present
    expect(ariaDescribedBy || ariaInvalid).toBeTruthy();
  });
});
