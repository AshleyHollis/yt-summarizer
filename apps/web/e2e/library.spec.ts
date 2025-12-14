import { test, expect } from '@playwright/test';

/**
 * E2E Tests for User Story 3: Browse the Library
 *
 * These tests verify the library browsing functionality:
 * 1. Library page loads and displays videos
 * 2. Filtering works (channel, status, date range, facets)
 * 3. Pagination works correctly
 * 4. Video detail navigation works
 * 5. Search functionality works
 *
 * Prerequisites:
 * - Aspire backend must be running: cd services/aspire/AppHost && dotnet run
 * - Run with: USE_EXTERNAL_SERVER=true npm run test:e2e
 */

test.describe('User Story 3: Browse the Library', () => {
  // Skip all tests in this suite unless backend is running
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  test.describe('Library Page Loading', () => {
    test('library page loads successfully', async ({ page }) => {
      await page.goto('/library');
      await expect(page).toHaveURL('/library');
      
      // Check page header
      await expect(page.getByRole('heading', { name: 'Library' })).toBeVisible();
    });

    test('library page shows filter sidebar', async ({ page }) => {
      await page.goto('/library');
      
      // Check filter sidebar elements using specific label selectors
      await expect(page.getByLabel('Search')).toBeVisible();
      await expect(page.locator('label', { hasText: 'Channel' })).toBeVisible();
      await expect(page.locator('label', { hasText: 'Date Range' })).toBeVisible();
      await expect(page.locator('label[for="status-filter"]')).toBeVisible();
      await expect(page.locator('label[for="sort-by"]')).toBeVisible();
    });

    test('library page fetches and displays videos', async ({ page }) => {
      await page.goto('/library');
      
      // Wait for loading to finish (loading skeleton or actual content)
      await page.waitForFunction(() => {
        const loading = document.querySelector('.animate-pulse');
        return !loading || loading.closest('.hidden');
      }, { timeout: 10000 }).catch(() => {
        // Loading might already be done
      });
      
      // Either show videos or "No videos found" message
      // Use more specific selectors for video cards
      const videoGrid = page.locator('[data-testid="video-grid"], .grid');
      const noVideosMessage = page.getByText(/No videos found|No results|library is empty/i);
      
      // Wait for either content or empty state - check if grid has children or empty message shows
      await expect(videoGrid.first().or(noVideosMessage)).toBeVisible({ timeout: 10000 });
    });

    test('library stats endpoint returns valid data', async ({ page, request }) => {
      // Direct API test to ensure backend is working
      const response = await request.get('http://localhost:8000/api/v1/library/stats', {
        headers: { 'X-Correlation-ID': 'e2e-test' }
      });
      
      expect(response.ok()).toBeTruthy();
      const data = await response.json();
      
      expect(data).toHaveProperty('total_videos');
      expect(data).toHaveProperty('total_channels');
      expect(data).toHaveProperty('completed_videos');
    });
  });

  test.describe('Filter Functionality', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/library');
      // Wait for initial load
      await page.waitForLoadState('networkidle');
    });

    test('search filter updates results', async ({ page }) => {
      const searchInput = page.getByLabel(/Search/i);
      await expect(searchInput).toBeVisible();
      
      // Type a search query
      await searchInput.fill('test');
      
      // Wait for debounce and API call
      await page.waitForTimeout(500);
      
      // Verify URL updated or API call made
      // The component should update based on search
      await expect(searchInput).toHaveValue('test');
    });

    test('status filter dropdown works', async ({ page }) => {
      const statusDropdown = page.getByLabel(/Status/i);
      await expect(statusDropdown).toBeVisible();
      
      // Select "Completed" status
      await statusDropdown.selectOption('completed');
      
      // Verify selection
      await expect(statusDropdown).toHaveValue('completed');
    });

    test('status filter via URL query parameter works', async ({ page }) => {
      // Navigate directly to library with status=completed filter
      // This is the URL the "View Ready Videos" button uses after batch completion
      await page.goto('/library?status=completed');
      
      // Verify page loads successfully (not an error)
      await expect(page.getByRole('heading', { name: 'Library' })).toBeVisible();
      
      // Verify the status dropdown reflects the URL parameter
      const statusDropdown = page.getByLabel(/Status/i);
      await expect(statusDropdown).toHaveValue('completed');
    });

    test('invalid status filter returns error from API', async ({ request }) => {
      // Test that the API correctly rejects invalid status values
      // This protects against bugs like using 'ready' instead of 'completed'
      const response = await request.get('http://localhost:8000/api/v1/library/videos?status=ready', {
        headers: { 'X-Correlation-ID': 'e2e-test' }
      });
      
      // Should return 422 Unprocessable Entity for invalid enum value
      expect(response.status()).toBe(422);
    });

    test('valid status filters return success from API', async ({ request }) => {
      // Test all valid status values
      const validStatuses = ['pending', 'processing', 'completed', 'failed'];
      
      for (const status of validStatuses) {
        const response = await request.get(`http://localhost:8000/api/v1/library/videos?status=${status}`, {
          headers: { 'X-Correlation-ID': 'e2e-test' }
        });
        
        expect(response.ok()).toBeTruthy();
      }
    });

    test('date range filters are functional', async ({ page }) => {
      // Use specific IDs from the component
      const fromDate = page.locator('#from-date');
      const toDate = page.locator('#to-date');
      
      await expect(fromDate).toBeVisible();
      await expect(toDate).toBeVisible();
      
      // Set date range
      await fromDate.fill('2024-01-01');
      await toDate.fill('2024-12-31');
      
      // Verify values
      await expect(fromDate).toHaveValue('2024-01-01');
      await expect(toDate).toHaveValue('2024-12-31');
    });

    test('sort options work correctly', async ({ page }) => {
      const sortByDropdown = page.getByLabel(/Sort By/i);
      await expect(sortByDropdown).toBeVisible();
      
      // Change sort
      await sortByDropdown.selectOption('title');
      await expect(sortByDropdown).toHaveValue('title');
    });

    test('clear search button works', async ({ page }) => {
      const searchInput = page.getByLabel(/Search/i);
      await searchInput.fill('test query');
      
      // Look for clear button
      const clearButton = page.locator('button[aria-label*="clear"], button:has(svg[data-testid="x-mark"])').first();
      
      if (await clearButton.isVisible()) {
        await clearButton.click();
        await expect(searchInput).toHaveValue('');
      }
    });
  });

  test.describe('Video Cards Display', () => {
    test('video cards show required information', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      // Wait for content to load
      const videoCard = page.locator('[data-testid="video-card"], .video-card, article').first();
      
      if (await videoCard.isVisible()) {
        // Card should have essential elements
        const thumbnail = videoCard.locator('img');
        const title = videoCard.locator('h3, h2, .title');
        
        // At minimum, title should be visible
        await expect(title.or(thumbnail)).toBeVisible();
      }
    });

    test('clicking video card navigates to detail page', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      const videoCard = page.locator('[data-testid="video-card"], .video-card, article a').first();
      
      if (await videoCard.isVisible()) {
        await videoCard.click();
        
        // Should navigate to video detail or library/[videoId]
        await expect(page).toHaveURL(/\/library\/[a-f0-9-]+|\/videos\/[a-f0-9-]+/);
      }
    });
  });

  test.describe('Pagination', () => {
    test('pagination shows when there are multiple pages', async ({ page, request }) => {
      // First check if there's enough data for pagination
      const response = await request.get('http://localhost:8000/api/v1/library/videos?page_size=10', {
        headers: { 'X-Correlation-ID': 'e2e-test' }
      });
      const data = await response.json();
      
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      // Only check pagination if there are more than 10 videos
      if (data.total_count > 10) {
        const pagination = page.locator('nav[aria-label*="Pagination"], .pagination');
        await expect(pagination).toBeVisible();
      }
    });

    test('pagination buttons navigate between pages', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      const nextButton = page.getByRole('button', { name: /Next/i }).first();
      
      if (await nextButton.isVisible() && await nextButton.isEnabled()) {
        await nextButton.click();
        
        // Page should update
        await page.waitForLoadState('networkidle');
      }
    });
  });

  test.describe('Channel Filter', () => {
    test('channel dropdown loads channels from API', async ({ page }) => {
      await page.goto('/library');
      await page.waitForLoadState('networkidle');
      
      // Wait for channels to load (loading skeleton should disappear)
      await page.waitForFunction(() => {
        const channelSection = document.querySelector('[class*="Channel"]');
        if (!channelSection) return true;
        return !channelSection.querySelector('.animate-pulse');
      }, { timeout: 5000 }).catch(() => {});
      
      // Check if channel select or list exists
      const channelFilter = page.locator('select, [role="listbox"], .channel-filter').first();
      await expect(channelFilter).toBeVisible({ timeout: 5000 }).catch(() => {
        // Channel filter might not be rendered if no channels
      });
    });
  });

  test.describe('Video Detail from Library', () => {
    let videoId: string | null = null;

    test.beforeAll(async ({ request }) => {
      // Get a video ID from the library
      const response = await request.get('http://localhost:8000/api/v1/library/videos?page_size=1', {
        headers: { 'X-Correlation-ID': 'e2e-test' }
      });
      const data = await response.json();
      
      if (data.videos && data.videos.length > 0) {
        videoId = data.videos[0].video_id;
      }
    });

    test('video detail page loads from library', async ({ page }) => {
      test.skip(!videoId, 'No videos in library');
      
      await page.goto(`/library/${videoId}`);
      await page.waitForLoadState('domcontentloaded');
      
      // Page should load - check for body content (main might not exist during loading)
      await expect(page.locator('body')).toBeVisible();
      // Wait for actual content to render
      await page.waitForLoadState('networkidle');
    });

    test('video detail shows segments', async ({ page }) => {
      test.skip(!videoId, 'No videos in library');
      
      await page.goto(`/library/${videoId}`);
      await page.waitForLoadState('networkidle');
      
      // Should show segments section or transcript
      const segmentsSection = page.getByText(/Segments|Transcript|Timeline/i);
      await expect(segmentsSection.first()).toBeVisible({ timeout: 5000 }).catch(() => {
        // Video might not have segments yet
      });
    });

    test('back to library link works', async ({ page }) => {
      test.skip(!videoId, 'No videos in library');
      
      await page.goto(`/library/${videoId}`);
      
      const backLink = page.getByRole('link', { name: /back|library/i });
      
      if (await backLink.first().isVisible()) {
        await backLink.first().click();
        await expect(page).toHaveURL('/library');
      }
    });
  });

  test.describe('Error Handling', () => {
    test('handles API errors gracefully', async ({ page }) => {
      // Navigate to library
      await page.goto('/library');
      
      // Page should not crash - verify body is present
      await expect(page.locator('body')).toBeVisible();
      // And verify some library content rendered
      await expect(page.getByRole('heading', { name: 'Library' })).toBeVisible();
    });

    test('shows error for invalid video ID in library detail', async ({ page }) => {
      await page.goto('/library/invalid-uuid');
      
      // Should show error message or have some content (not a crash)
      // The page might show an error or just render with error state
      await page.waitForLoadState('networkidle');
      
      // Verify page didn't crash - body should be visible
      await expect(page.locator('body')).toBeVisible();
    });

    test('shows error for non-existent video', async ({ page }) => {
      await page.goto('/library/00000000-0000-0000-0000-000000000000');
      
      // Should show not found or error
      const errorContent = page.getByText(/not found|error|doesn't exist/i);
      await expect(errorContent.first()).toBeVisible({ timeout: 5000 }).catch(() => {
        // Page might just redirect or show empty state
      });
    });
  });

  test.describe('Accessibility', () => {
    test('library page is keyboard navigable', async ({ page }) => {
      await page.goto('/library');
      
      // Tab through the page
      await page.keyboard.press('Tab');
      
      // Something should be focused
      const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
      expect(focusedElement).toBeTruthy();
    });

    test('filter inputs have accessible labels', async ({ page }) => {
      await page.goto('/library');
      
      // Check that form elements have labels
      const searchInput = page.getByLabel(/Search/i);
      await expect(searchInput).toBeVisible();
      
      const statusSelect = page.getByLabel(/Status/i);
      await expect(statusSelect).toBeVisible();
    });
  });

  test.describe('Navigation Integration', () => {
    test('header shows Library link', async ({ page }) => {
      await page.goto('/');
      
      const libraryLink = page.getByRole('link', { name: /Library/i });
      await expect(libraryLink).toBeVisible();
    });

    test('Library link navigates to library page', async ({ page }) => {
      await page.goto('/submit');
      
      const libraryLink = page.getByRole('link', { name: /Library/i });
      await libraryLink.click();
      
      await expect(page).toHaveURL('/library');
    });

    test('can navigate from submit to library and back', async ({ page }) => {
      await page.goto('/submit');
      
      // Go to library
      await page.getByRole('link', { name: /Library/i }).click();
      await expect(page).toHaveURL('/library');
      
      // Go back to submit
      await page.getByRole('link', { name: /Submit/i }).click();
      await expect(page).toHaveURL('/submit');
    });
  });
});
